//! Oplog retention and compaction over `oplog_db`.

use std::time::Duration;

use crate::{DeviceId, Hlc, OpId, OrderKey};
use rusqlite::params;

use super::SqliteError as GCError;
use super::coverage;

/// Default retention horizon (30 days).
pub const DEFAULT_RETENTION_HORIZON: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const HLC_SECONDS_SHIFT: u32 = 32;

#[derive(Debug, Clone)]
pub struct CompactionReport {
    pub store: String,
    pub watermark: Option<OrderKey>,
    pub pruned: usize,
}

pub fn compaction_watermark(
    snapshot_watermark: Option<OrderKey>,
    now: Hlc,
    horizon: Duration,
) -> Option<OrderKey> {
    let snap = snapshot_watermark?;
    Some(snap.min(horizon_watermark(now, horizon)))
}

pub fn horizon_watermark(now: Hlc, horizon: Duration) -> OrderKey {
    let now_secs = now.0 >> HLC_SECONDS_SHIFT;
    let floor_secs = now_secs.saturating_sub(horizon.as_secs());
    OrderKey {
        hlc: Hlc(floor_secs << HLC_SECONDS_SHIFT),
        device: DeviceId::from_bytes([0; 32]),
        op_id: OpId::from_bytes([0; 32]),
    }
}

pub fn rows_with_ops_below(
    conn: &rusqlite::Connection,
    store: &str,
    c: OrderKey,
) -> Result<Vec<(String, String)>, GCError> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT table_name, row_pk FROM oplog_db.oplog
             WHERE store_id = ?1 AND (hlc, device_id, op_id) < (?2, ?3, ?4)",
        )
        .map_err(|e| GCError::Other(format!("retention candidates prepare: {e}")))?;
    let rows = stmt
        .query_map(
            rusqlite::params![
                store,
                c.hlc.0 as i64,
                c.device.as_bytes().as_slice(),
                c.op_id.as_bytes().as_slice(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|e| GCError::Other(format!("retention candidates query: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| GCError::Other(format!("retention candidates row: {e}")))?);
    }
    Ok(out)
}

pub fn delete_row_below(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
    c: OrderKey,
    keep: Option<&OpId>,
) -> Result<usize, GCError> {
    let deleted = match keep {
        Some(anchor) => conn
            .execute(
                "DELETE FROM oplog_db.oplog
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
                   AND (hlc, device_id, op_id) < (?4, ?5, ?6)
                   AND op_id != ?7",
                rusqlite::params![
                    store,
                    table,
                    row_pk,
                    c.hlc.0 as i64,
                    c.device.as_bytes().as_slice(),
                    c.op_id.as_bytes().as_slice(),
                    anchor.as_bytes().as_slice(),
                ],
            )
            .map_err(|e| GCError::Other(format!("retention prune (anchored): {e}")))?,
        None => conn
            .execute(
                "DELETE FROM oplog_db.oplog
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
                   AND (hlc, device_id, op_id) < (?4, ?5, ?6)",
                rusqlite::params![
                    store,
                    table,
                    row_pk,
                    c.hlc.0 as i64,
                    c.device.as_bytes().as_slice(),
                    c.op_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|e| GCError::Other(format!("retention prune (whole row): {e}")))?,
    };
    Ok(deleted)
}

#[derive(Debug, Clone, Copy)]
pub struct CompactionPolicy {
    pub keep_per_row: u32,
    pub max_deletes_per_pass: usize,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            keep_per_row: 3,
            max_deletes_per_pass: 500_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OplogCompaction {
    pub deleted_ops: usize,
    pub reclaimed_bytes: u64,
    pub used_legacy_lww_index: bool,
    pub relay_floor: u64,
    pub bounds: CompactionBounds,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CompactionBounds {
    pub peers: i64,
    pub horizon_floor: i64,
    pub ack_floor: i64,
    pub safe_floor: i64,
    pub scan_resumed_after: i64,
    pub scanned: usize,
    pub candidates: usize,
    pub scan_cursor: i64,
}

pub const DELETE_CHUNK: usize = 500;
pub const SCAN_CURSOR_KEY: &str = "retention.candidate_scan_after";

pub fn current_relay_floor(conn: &rusqlite::Connection) -> Result<u64, GCError> {
    conn.query_row(
        "SELECT compacted_through_seq FROM oplog_db.mesh_relay_state WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(|floor| floor as u64)
    .map_err(|e| GCError::Other(format!("compaction floor readback: {e}")))
}

pub fn safe_relay_floor(
    conn: &rusqlite::Connection,
    local_device: &DeviceId,
    horizon: Duration,
) -> Result<CompactionBounds, GCError> {
    let peers: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE trusted = 1 AND device_id != ?1",
            params![local_device.to_hex()],
            |row| row.get(0),
        )
        .map_err(|e| GCError::Other(format!("compaction peer count: {e}")))?;
    let cutoff = chrono::Utc::now().timestamp() - horizon.as_secs() as i64;
    let horizon_floor: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(relay_seq), 0) FROM oplog_db.oplog_arrivals WHERE arrived_at <= ?1",
            params![cutoff],
            |row| row.get(0),
        )
        .map_err(|e| GCError::Other(format!("compaction relay floor: {e}")))?;
    if peers == 0 {
        return Ok(CompactionBounds {
            peers,
            horizon_floor,
            ack_floor: 0,
            safe_floor: horizon_floor,
            ..Default::default()
        });
    }
    let epoch = coverage::current_stream_epoch(conn)?;
    let dormant_before =
        (chrono::Utc::now() - chrono::Duration::seconds(horizon.as_secs() as i64)).to_rfc3339();
    let ack =
        coverage::min_peer_ack(conn, local_device, &epoch, Some(&dormant_before))?.unwrap_or(0);
    let ack_floor = i64::try_from(ack).unwrap_or(i64::MAX);
    Ok(CompactionBounds {
        peers,
        horizon_floor,
        ack_floor,
        safe_floor: horizon_floor.max(ack_floor),
        ..Default::default()
    })
}

#[derive(Clone, Copy)]
pub enum CompactionProbeIndex {
    Applied,
    LegacyLww,
}

pub struct CompactionScan {
    pub candidates: Vec<(OpId, i64)>,
    pub next_cursor: i64,
    pub scanned: usize,
}

impl CompactionProbeIndex {
    pub fn detect(conn: &rusqlite::Connection) -> Result<Self, GCError> {
        let has_applied_index: bool = conn
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM oplog_db.sqlite_master
                    WHERE type = 'index' AND name = 'idx_oplog_applied'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| GCError::Other(format!("compaction index probe: {e}")))?;
        Ok(if has_applied_index {
            Self::Applied
        } else {
            Self::LegacyLww
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Applied => "idx_oplog_applied",
            Self::LegacyLww => "idx_oplog_lww",
        }
    }
}

fn is_self_draining_bulk_table(store: &str, table: &str) -> bool {
    store == "proxydb"
        && matches!(
            table,
            "items"
                | "sequences"
                | "widget_files"
                | "party_files"
                | "conversations"
                | "conversation_participants"
                | "conversation_jobs"
                | "message_attachments"
        )
}

const SELF_DRAINING_SQL_FILTER: &str = "(store_id = 'proxydb' AND table_name IN ('items', 'sequences', 'widget_files', 'party_files', 'conversations', 'conversation_participants', 'conversation_jobs', 'message_attachments'))";

pub fn compaction_candidates(
    conn: &rusqlite::Connection,
    policy: &CompactionPolicy,
    safe_floor: i64,
    deadline: std::time::Instant,
    resume_after: i64,
    probe_index: CompactionProbeIndex,
) -> Result<CompactionScan, GCError> {
    let head: i64 = conn
        .prepare_cached("SELECT COALESCE(MAX(relay_seq), 0) FROM oplog_db.oplog_arrivals")
        .map_err(|e| GCError::Other(format!("compaction head prepare: {e}")))?
        .query_row([], |row| row.get(0))
        .map_err(|e| GCError::Other(format!("compaction head: {e}")))?;

    let probe_index_name = probe_index.name();
    let mut newer = conn
        .prepare(&format!(
            "SELECT 1 FROM oplog_db.oplog INDEXED BY {probe_index_name}
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
               AND (hlc, device_id, op_id) > (?4, ?5, ?6)
             LIMIT 1 OFFSET ?7"
        ))
        .map_err(|e| GCError::Other(format!("compaction newer prepare: {e}")))?;
    let mut older = conn
        .prepare(&format!(
            "SELECT 1 FROM oplog_db.oplog INDEXED BY {probe_index_name}
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
               AND (hlc, device_id, op_id) < (?4, ?5, ?6)
             LIMIT 1"
        ))
        .map_err(|e| GCError::Other(format!("compaction older prepare: {e}")))?;
    let mut edge_pin = conn
        .prepare_cached("SELECT 1 FROM oplog_db.pending_graph_edges WHERE edge_op_id = ?1 LIMIT 1")
        .map_err(|e| GCError::Other(format!("compaction edge pin prepare: {e}")))?;
    let mut fire_pin = conn
        .prepare_cached(
            "SELECT 1 FROM oplog_db.move_callback_fires WHERE dispatched = 0 AND resolution_op_id = ?1 LIMIT 1",
        )
        .map_err(|e| GCError::Other(format!("compaction fire pin prepare: {e}")))?;
    let mut head_pin = conn
        .prepare_cached(
            "SELECT 1 FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND op_id = ?4
             LIMIT 1",
        )
        .map_err(|e| GCError::Other(format!("compaction head pin prepare: {e}")))?;
    let mut projection_pin = conn
        .prepare_cached("SELECT 1 FROM oplog_db.proxydb_projection_queue WHERE op_id = ?1 LIMIT 1")
        .map_err(|e| GCError::Other(format!("compaction projection pin prepare: {e}")))?;
    let mut replay_pin = conn
        .prepare_cached(
            "SELECT 1 FROM external_row_replay_queue
             WHERE op_id = ?1 AND state != 'failed' LIMIT 1",
        )
        .map_err(|e| GCError::Other(format!("compaction replay pin prepare: {e}")))?;

    const SCAN_PAGE: usize = 2048;
    const LEGACY_LWW_SCAN_CAP: usize = 16_384;
    let scan_cap = policy.max_deletes_per_pass.saturating_mul(4).max(SCAN_PAGE);
    let scan_cap = if matches!(probe_index, CompactionProbeIndex::LegacyLww) {
        scan_cap.min(LEGACY_LWW_SCAN_CAP)
    } else {
        scan_cap
    };
    let mut candidates = Vec::new();
    let mut scanned = 0usize;
    let mut after_seq = resume_after.max(0);
    let mut exhausted = false;
    'scan: while candidates.len() < policy.max_deletes_per_pass
        && scanned < scan_cap
        && std::time::Instant::now() < deadline
    {
        let page = conn
            .prepare_cached(
                "SELECT a.relay_seq, a.op_id, o.store_id, o.table_name, o.row_pk,
                        o.hlc, o.device_id
                 FROM oplog_db.oplog_arrivals AS a
                 JOIN oplog_db.oplog AS o ON o.op_id = a.op_id
                 WHERE o.applied = 1
                   AND a.relay_seq > ?1 AND a.relay_seq <= ?2 AND a.relay_seq < ?3
                 ORDER BY a.relay_seq
                 LIMIT ?4",
            )
            .map_err(|e| GCError::Other(format!("compaction scan prepare: {e}")))?
            .query_map(
                params![after_seq, safe_floor, head, SCAN_PAGE as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .map_err(|e| GCError::Other(format!("compaction scan: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| GCError::Other(format!("compaction scan row: {e}")))?;
        if page.is_empty() {
            exhausted = true;
            break;
        }
        for (relay_seq, op_id, store, table, row_pk, hlc, device) in page {
            after_seq = relay_seq;
            scanned += 1;
            if std::time::Instant::now() >= deadline {
                break 'scan;
            }
            let bulk_drain = is_self_draining_bulk_table(&store, &table);
            if !bulk_drain {
                let shadowed = policy.keep_per_row == 0
                    || newer
                        .exists(params![
                            store,
                            table,
                            row_pk,
                            hlc,
                            device,
                            op_id,
                            i64::from(policy.keep_per_row) - 1
                        ])
                        .map_err(|e| GCError::Other(format!("compaction newer probe: {e}")))?;
                if !shadowed {
                    continue;
                }
                let has_older = older
                    .exists(params![store, table, row_pk, hlc, device, op_id])
                    .map_err(|e| GCError::Other(format!("compaction older probe: {e}")))?;
                if !has_older {
                    continue;
                }
            }
            if std::time::Instant::now() >= deadline {
                break 'scan;
            }
            if edge_pin
                .exists(params![op_id])
                .map_err(|e| GCError::Other(format!("compaction edge probe: {e}")))?
                || fire_pin
                    .exists(params![op_id])
                    .map_err(|e| GCError::Other(format!("compaction fire probe: {e}")))?
                || (!bulk_drain
                    && head_pin
                        .exists(params![store, table, row_pk, op_id])
                        .map_err(|e| GCError::Other(format!("compaction head probe: {e}")))?)
                || projection_pin
                    .exists(params![op_id])
                    .map_err(|e| GCError::Other(format!("compaction projection probe: {e}")))?
                || replay_pin
                    .exists(params![op_id])
                    .map_err(|e| GCError::Other(format!("compaction replay probe: {e}")))?
            {
                continue;
            }
            let Ok(op_id) = <[u8; 32]>::try_from(op_id.as_slice()) else {
                continue;
            };
            candidates.push((OpId::from_bytes(op_id), relay_seq));
            if candidates.len() >= policy.max_deletes_per_pass {
                break 'scan;
            }
        }
    }
    Ok(CompactionScan {
        candidates,
        next_cursor: if exhausted { 0 } else { after_seq },
        scanned,
    })
}

pub fn delete_ops_chunk(
    conn: &rusqlite::Connection,
    chunk: &[(OpId, i64)],
) -> Result<(usize, u64), GCError> {
    let placeholders = (0..chunk.len())
        .map(|i| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let ids = chunk
        .iter()
        .map(|(op_id, _)| op_id.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let pins = "NOT IN (SELECT edge_op_id FROM oplog_db.pending_graph_edges)
                AND {alias}.op_id NOT IN
                    (SELECT resolution_op_id FROM oplog_db.move_callback_fires WHERE dispatched = 0)
                AND {alias}.op_id NOT IN
                    (SELECT op_id FROM oplog_db.proxydb_projection_queue)
                AND {alias}.op_id NOT IN
                    (SELECT op_id FROM external_row_replay_queue WHERE state != 'failed')";
    let oplog_pins = pins.replace("{alias}", "oplog");
    let arrival_pins = pins.replace("{alias}", "oplog_arrivals");
    let oplog_head_pin = format!(
        "({SELF_DRAINING_SQL_FILTER} OR NOT EXISTS (
             SELECT 1 FROM oplog_db.oplog_heads AS heads
             WHERE heads.store_id = oplog.store_id
               AND heads.table_name = oplog.table_name
               AND heads.row_pk = oplog.row_pk
               AND heads.op_id = oplog.op_id
         ))"
    );
    let arrival_head_pin = format!(
        "NOT EXISTS (
             SELECT 1
             FROM oplog_db.oplog AS pinned_op
             JOIN oplog_db.oplog_heads AS heads
               ON heads.store_id = pinned_op.store_id
              AND heads.table_name = pinned_op.table_name
              AND heads.row_pk = pinned_op.row_pk
              AND heads.op_id = pinned_op.op_id
             WHERE pinned_op.op_id = oplog_arrivals.op_id
               AND NOT (pinned_op.store_id = 'proxydb' AND pinned_op.table_name IN ('items', 'sequences', 'widget_files', 'party_files', 'conversations', 'conversation_participants', 'conversation_jobs', 'message_attachments'))
         )"
    );

    let (bytes, floor): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COALESCE(SUM(LENGTH(oplog.envelope) + LENGTH(oplog.payload)), 0),
                        COALESCE(MAX(arrivals.relay_seq), 0)
                 FROM oplog_db.oplog
                 JOIN oplog_db.oplog_arrivals AS arrivals ON arrivals.op_id = oplog.op_id
                 WHERE oplog.op_id IN ({placeholders})
                   AND oplog.op_id {oplog_pins}
                   AND {oplog_head_pin}"
            ),
            rusqlite::params_from_iter(ids.iter()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| GCError::Other(format!("compaction chunk stats: {e}")))?;
    conn.execute(
        &format!(
            "UPDATE oplog_db.oplog_heads
             SET payload = X''
             WHERE op_id IN ({placeholders})
               AND {SELF_DRAINING_SQL_FILTER}
               AND LENGTH(payload) > 64"
        ),
        rusqlite::params_from_iter(ids.iter()),
    )
    .map_err(|e| GCError::Other(format!("compaction head payload trim: {e}")))?;
    conn.execute(
        &format!(
            "DELETE FROM oplog_db.oplog_arrivals
             WHERE op_id IN ({placeholders}) AND op_id {arrival_pins}
               AND {arrival_head_pin}"
        ),
        rusqlite::params_from_iter(ids.iter()),
    )
    .map_err(|e| GCError::Other(format!("compaction arrival delete: {e}")))?;
    let deleted = conn
        .execute(
            &format!(
                "DELETE FROM oplog_db.oplog
                 WHERE op_id IN ({placeholders}) AND op_id {oplog_pins}
                   AND {oplog_head_pin}"
            ),
            rusqlite::params_from_iter(ids.iter()),
        )
        .map_err(|e| GCError::Other(format!("compaction oplog delete: {e}")))?;
    conn.execute(
        &format!(
            "DELETE FROM oplog_db.mesh_verified_ops
             WHERE op_id IN ({placeholders})
               AND op_id NOT IN (SELECT op_id FROM oplog_db.oplog)"
        ),
        rusqlite::params_from_iter(ids.iter()),
    )
    .map_err(|e| GCError::Other(format!("compaction verified_ops delete: {e}")))?;
    if deleted > 0 {
        conn.execute(
            "UPDATE oplog_db.mesh_relay_state
             SET compacted_through_seq = MAX(compacted_through_seq, ?1)
             WHERE singleton = 1",
            params![floor],
        )
        .map_err(|e| GCError::Other(format!("compaction floor advance: {e}")))?;
    }
    Ok((deleted, bytes as u64))
}
