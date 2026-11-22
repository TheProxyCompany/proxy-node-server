//! Oplog retention bounds, watermarks, and incremental vacuum over `oplog_db`.

use std::time::Duration;

use crate::{DeviceId, Hlc, OpId, OrderKey};
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;
use super::coverage;
use super::retention_pins::{PinTables, store_head_op_ids};

pub use super::retention_ops::{
    CompactionProbeIndex, CompactionScan, OrphanOplogScan, compaction_candidates,
    compaction_candidates_with_lww, delete_ops_chunk, delete_ops_chunk_with_floor,
    orphan_oplog_candidates,
};

pub const VERIFIED_OPS_SCAN_CURSOR_KEY: &str = "retention.verified_ops_scan_after";
pub const ORPHAN_OPLOG_SCAN_CURSOR_KEY: &str = "retention.orphan_oplog_scan_after";

/// Default retention horizon (7 days).
pub const DEFAULT_RETENTION_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Maximum age of a peer's `mesh_peer_acks` entry before it stops pinning `ack_floor` (7 days).
pub const PEER_ACK_TTL: Duration = DEFAULT_RETENTION_HORIZON;

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
    let horizon_floor = horizon_watermark(now, horizon);
    match snapshot_watermark {
        Some(snap) => Some(snap.min(horizon_floor)),
        None => Some(horizon_floor),
    }
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
            params![
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
    let candidate_ids = {
        let sql = if keep.is_some() {
            "SELECT op_id FROM oplog_db.oplog
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
               AND applied = 1
               AND (hlc, device_id, op_id) < (?4, ?5, ?6)
               AND op_id != ?7"
        } else {
            "SELECT op_id FROM oplog_db.oplog
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
               AND applied = 1
               AND (hlc, device_id, op_id) < (?4, ?5, ?6)"
        };
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| GCError::Other(format!("retention prune select prepare: {e}")))?;
        let extract = |row: &rusqlite::Row<'_>| row.get::<_, Vec<u8>>(0);
        let mapped = match keep {
            Some(anchor) => stmt.query_map(
                params![
                    store,
                    table,
                    row_pk,
                    c.hlc.0 as i64,
                    c.device.as_bytes().as_slice(),
                    c.op_id.as_bytes().as_slice(),
                    anchor.as_bytes().as_slice(),
                ],
                extract,
            ),
            None => stmt.query_map(
                params![
                    store,
                    table,
                    row_pk,
                    c.hlc.0 as i64,
                    c.device.as_bytes().as_slice(),
                    c.op_id.as_bytes().as_slice(),
                ],
                extract,
            ),
        }
        .map_err(|e| GCError::Other(format!("retention prune select: {e}")))?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| GCError::Other(format!("retention prune select row: {e}")))?
    };
    if candidate_ids.is_empty() {
        return Ok(0);
    }
    let tables = PinTables::detect(conn)?;
    let store_heads = store_head_op_ids(conn, &tables)?;
    let filtered: Vec<Vec<u8>> = candidate_ids
        .into_iter()
        .filter(|raw| {
            <[u8; 32]>::try_from(raw.as_slice()).is_ok_and(|arr| !store_heads.contains(&arr))
        })
        .collect();
    if filtered.is_empty() {
        return Ok(0);
    }
    let mut deleted = 0usize;
    for chunk in filtered.chunks(DELETE_CHUNK) {
        let (sub_deleted, _, _) =
            super::retention_ops::delete_ops_ids(conn, chunk, &tables, false)?;
        deleted += sub_deleted;
    }
    Ok(deleted)
}

#[derive(Debug, Clone, Copy)]
pub struct CompactionPolicy {
    pub keep_per_row: u32,
    pub batch_limit: usize,
    pub candidate_scan_cap: usize,
    pub max_deletes_per_pass: usize,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            keep_per_row: 3,
            batch_limit: 10_000,
            candidate_scan_cap: 50_000,
            max_deletes_per_pass: 500_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OplogCompaction {
    pub deleted_ops: usize,
    pub reclaimed_bytes: u64,
    pub pruned_verified_ops: usize,
    pub vacuumed_pages: usize,
    pub used_legacy_lww_index: bool,
    pub relay_floor: u64,
    pub orphan_oplog_cursor_active: bool,
    pub bounds: CompactionBounds,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CompactionBounds {
    pub peers: i64,
    pub horizon_floor: i64,
    pub ack_floor: i64,
    pub safe_floor: i64,
    pub lww_floor: i64,
    pub horizon_hlc_max: i64,
    pub ack_covers_horizon: bool,
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

/// Reclaim up to `max_pages` freelist pages from `oplog_db` when `auto_vacuum = INCREMENTAL`.
pub fn incremental_vacuum_oplog(
    conn: &rusqlite::Connection,
    max_pages: usize,
) -> Result<usize, GCError> {
    if max_pages == 0 {
        return Ok(0);
    }
    let mode: i64 = conn
        .query_row("PRAGMA oplog_db.auto_vacuum", [], |row| row.get(0))
        .map_err(|e| GCError::Other(format!("read oplog_db auto_vacuum: {e}")))?;
    if mode != 2 {
        return Ok(0);
    }
    let before: i64 = conn
        .query_row("PRAGMA oplog_db.freelist_count", [], |row| row.get(0))
        .map_err(|e| GCError::Other(format!("read oplog_db freelist_count: {e}")))?;
    if before <= 0 {
        return Ok(0);
    }
    conn.execute_batch(&format!("PRAGMA oplog_db.incremental_vacuum({max_pages});"))
        .map_err(|e| GCError::Other(format!("oplog_db incremental_vacuum: {e}")))?;
    let after: i64 = conn
        .query_row("PRAGMA oplog_db.freelist_count", [], |row| row.get(0))
        .map_err(|e| GCError::Other(format!("re-read oplog_db freelist_count: {e}")))?;
    Ok(usize::try_from((before - after).max(0)).unwrap_or(0))
}

fn horizon_relay_floor(conn: &rusqlite::Connection, cutoff: i64) -> Result<i64, GCError> {
    let oldest: Option<(i64, i64)> = conn
        .query_row(
            "SELECT relay_seq, arrived_at FROM oplog_db.oplog_arrivals
             ORDER BY relay_seq ASC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| GCError::Other(format!("compaction oldest arrival: {e}")))?;
    let Some((min_seq, min_arrived_at)) = oldest else {
        return Ok(0);
    };
    if min_arrived_at > cutoff {
        return Ok(0);
    }
    let newest: (i64, i64) = conn
        .query_row(
            "SELECT relay_seq, arrived_at FROM oplog_db.oplog_arrivals
             ORDER BY relay_seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| GCError::Other(format!("compaction newest arrival: {e}")))?;
    if newest.1 <= cutoff {
        return Ok(newest.0);
    }
    let mut lo = min_seq;
    let mut hi = newest.0;
    let mut best = min_seq;
    let mut probe = conn
        .prepare_cached(
            "SELECT relay_seq, arrived_at FROM oplog_db.oplog_arrivals
             WHERE relay_seq <= ?1
             ORDER BY relay_seq DESC LIMIT 1",
        )
        .map_err(|e| GCError::Other(format!("compaction horizon probe prepare: {e}")))?;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let row: Option<(i64, i64)> = probe
            .query_row(params![mid], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .map_err(|e| GCError::Other(format!("compaction horizon probe: {e}")))?;
        let Some((seq, arrived_at)) = row else {
            lo = mid + 1;
            continue;
        };
        if arrived_at <= cutoff {
            best = best.max(seq);
            lo = mid + 1;
        } else {
            hi = seq - 1;
        }
    }
    Ok(best)
}

pub fn safe_relay_floor(
    conn: &rusqlite::Connection,
    local_device: &DeviceId,
    horizon: Duration,
) -> Result<CompactionBounds, GCError> {
    let peers: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM devices
             WHERE trusted = 1 AND device_id != ?1
               AND COALESCE(introduced_by, '') != 'local-history'",
            params![local_device.to_hex()],
            |row| row.get(0),
        )
        .map_err(|e| GCError::Other(format!("compaction peer count: {e}")))?;
    let now = chrono::Utc::now();
    let cutoff = now.timestamp() - horizon.as_secs() as i64;
    let horizon_hlc_max = if cutoff > 0 {
        (((cutoff as u64) << HLC_SECONDS_SHIFT) | 0xffff_ffff).min(i64::MAX as u64) as i64
    } else {
        0
    };
    let horizon_floor = horizon_relay_floor(conn, cutoff)?;
    if peers == 0 {
        return Ok(CompactionBounds {
            peers,
            horizon_floor,
            ack_floor: 0,
            safe_floor: horizon_floor,
            lww_floor: horizon_floor,
            horizon_hlc_max,
            ack_covers_horizon: true,
            ..Default::default()
        });
    }
    let epoch = coverage::current_stream_epoch(conn)?;
    let ack_ttl = horizon.min(PEER_ACK_TTL);
    let ack_cutoff_secs = now.timestamp() - ack_ttl.as_secs() as i64;
    let dormant_before = (now - chrono::Duration::seconds(ack_ttl.as_secs() as i64)).to_rfc3339();
    let active_ack = coverage::min_peer_ack_with_ttl(
        conn,
        local_device,
        &epoch,
        Some(&dormant_before),
        Some(ack_cutoff_secs),
    )?;
    let Some(ack) = active_ack else {
        return Ok(CompactionBounds {
            peers,
            horizon_floor,
            ack_floor: 0,
            safe_floor: horizon_floor,
            lww_floor: horizon_floor,
            horizon_hlc_max,
            ack_covers_horizon: true,
            ..Default::default()
        });
    };
    let ack_floor = i64::try_from(ack).unwrap_or(i64::MAX);
    let safe_floor = horizon_floor.min(ack_floor);
    Ok(CompactionBounds {
        peers,
        horizon_floor,
        ack_floor,
        safe_floor,
        lww_floor: safe_floor.max(ack_floor),
        horizon_hlc_max,
        ack_covers_horizon: ack_floor >= horizon_floor,
        ..Default::default()
    })
}

/// Bounded cursor-paged sweep over `oplog_db.mesh_verified_ops` that removes
/// orphaned rows absent from both `oplog_db.oplog` and `oplog_db.mesh_unverified_ops`.
pub fn prune_orphaned_verified_ops(
    conn: &rusqlite::Connection,
    after_op_id: &[u8],
    scan_limit: usize,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), GCError> {
    if scan_limit == 0 || !super::retention_ops::table_exists(conn, "mesh_verified_ops")? {
        return Ok((Vec::new(), Vec::new()));
    }
    let has_quarantine = super::retention_ops::table_exists(conn, "mesh_unverified_ops")?;
    let quarantine_join = if has_quarantine {
        "LEFT JOIN oplog_db.mesh_unverified_ops AS q ON q.claimed_op_id = v.op_id"
    } else {
        ""
    };
    let quarantine_missing = if has_quarantine {
        "AND q.claimed_op_id IS NULL"
    } else {
        ""
    };
    let rows: Vec<(Vec<u8>, bool)> = conn
        .prepare(&format!(
            "SELECT v.op_id, (o.op_id IS NULL {quarantine_missing})
             FROM (
                 SELECT op_id FROM oplog_db.mesh_verified_ops
                 WHERE op_id > ?1
                 ORDER BY op_id
                 LIMIT ?2
             ) AS v
             LEFT JOIN oplog_db.oplog AS o ON o.op_id = v.op_id
             {quarantine_join}
             ORDER BY v.op_id"
        ))
        .map_err(|e| GCError::Other(format!("verified_ops orphan scan prepare: {e}")))?
        .query_map(params![after_op_id, scan_limit as i64], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, bool>(1)?))
        })
        .map_err(|e| GCError::Other(format!("verified_ops orphan scan: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GCError::Other(format!("verified_ops orphan row: {e}")))?;
    let next_cursor = if rows.len() < scan_limit {
        Vec::new()
    } else {
        rows.last()
            .map(|(op_id, _)| op_id.clone())
            .unwrap_or_default()
    };
    let orphans = rows
        .into_iter()
        .filter_map(|(op_id, is_orphan)| is_orphan.then_some(op_id))
        .collect();
    Ok((orphans, next_cursor))
}
