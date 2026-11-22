//! Candidate scanning, chunked oplog deletion, and orphaned `mesh_verified_ops`
//! pruning over `oplog_db`.

use crate::OpId;
use rusqlite::{params, params_from_iter};

use super::SqliteError as GCError;
use super::retention::{CompactionPolicy, DELETE_CHUNK};

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

pub(crate) fn table_exists(conn: &rusqlite::Connection, name: &str) -> Result<bool, GCError> {
    conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM oplog_db.sqlite_master
            WHERE type = 'table' AND name = ?1
         )",
        params![name],
        |row| row.get(0),
    )
    .map_err(|e| GCError::Other(format!("probe oplog_db table {name}: {e}")))
}

/// `proxydb` tables whose rows are replaced wholesale, so the head op of a row
/// may be pruned like any other. Every other table keeps its live head.
const SELF_DRAINING_TABLES: &[&str] = &[
    "items",
    "sequences",
    "conversation_jobs",
    "message_attachments",
];

fn is_self_draining_bulk_table(store: &str, table: &str) -> bool {
    store == "proxydb" && SELF_DRAINING_TABLES.contains(&table)
}

/// SQL predicate that is true when the `alias` row belongs to a self-draining table.
fn self_draining_sql(alias: &str) -> String {
    let tables = SELF_DRAINING_TABLES
        .iter()
        .map(|table| format!("'{table}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("({alias}.store_id = 'proxydb' AND {alias}.table_name IN ({tables}))")
}

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
    let scan_cap = if matches!(probe_index, CompactionProbeIndex::LegacyLww) {
        policy.candidate_scan_cap.min(LEGACY_LWW_SCAN_CAP)
    } else {
        policy.candidate_scan_cap.max(SCAN_PAGE)
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
    if chunk.is_empty() {
        return Ok((0, 0));
    }
    let has_quarantine = table_exists(conn, "mesh_unverified_ops")?;
    let mut total_deleted = 0usize;
    let mut total_bytes = 0u64;
    let mut max_floor = 0i64;
    for sub in chunk.chunks(DELETE_CHUNK) {
        let (deleted, bytes, floor) = delete_ops_subchunk(conn, sub, has_quarantine)?;
        total_deleted += deleted;
        total_bytes += bytes;
        if deleted > 0 {
            max_floor = max_floor.max(floor);
        }
    }
    if total_deleted > 0 {
        conn.execute(
            "UPDATE oplog_db.mesh_relay_state
             SET compacted_through_seq = MAX(compacted_through_seq, ?1)
             WHERE singleton = 1",
            params![max_floor],
        )
        .map_err(|e| GCError::Other(format!("compaction floor advance: {e}")))?;
    }
    Ok((total_deleted, total_bytes))
}

fn delete_ops_subchunk(
    conn: &rusqlite::Connection,
    chunk: &[(OpId, i64)],
    has_quarantine: bool,
) -> Result<(usize, u64, i64), GCError> {
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
        "({} OR NOT EXISTS (
             SELECT 1 FROM oplog_db.oplog_heads AS heads
             WHERE heads.store_id = oplog.store_id
               AND heads.table_name = oplog.table_name
               AND heads.row_pk = oplog.row_pk
               AND heads.op_id = oplog.op_id
         ))",
        self_draining_sql("oplog")
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
               AND NOT {}
         )",
        self_draining_sql("pinned_op")
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
            params_from_iter(ids.iter()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| GCError::Other(format!("compaction chunk stats: {e}")))?;
    trim_upsert_head_payloads(conn, &placeholders, &ids)?;
    conn.execute(
        &format!(
            "DELETE FROM oplog_db.oplog_arrivals
             WHERE op_id IN ({placeholders}) AND op_id {arrival_pins}
               AND {arrival_head_pin}"
        ),
        params_from_iter(ids.iter()),
    )
    .map_err(|e| GCError::Other(format!("compaction arrival delete: {e}")))?;
    let deleted = conn
        .execute(
            &format!(
                "DELETE FROM oplog_db.oplog
                 WHERE op_id IN ({placeholders}) AND op_id {oplog_pins}
                   AND {oplog_head_pin}"
            ),
            params_from_iter(ids.iter()),
        )
        .map_err(|e| GCError::Other(format!("compaction oplog delete: {e}")))?;
    let quarantine_guard = if has_quarantine {
        "AND NOT EXISTS (
             SELECT 1 FROM oplog_db.mesh_unverified_ops AS q
             WHERE q.claimed_op_id = mesh_verified_ops.op_id
         )"
    } else {
        ""
    };
    conn.execute(
        &format!(
            "DELETE FROM oplog_db.mesh_verified_ops
             WHERE op_id IN ({placeholders})
               AND NOT EXISTS (
                   SELECT 1 FROM oplog_db.oplog AS o
                   WHERE o.op_id = mesh_verified_ops.op_id
               )
               {quarantine_guard}"
        ),
        params_from_iter(ids.iter()),
    )
    .map_err(|e| GCError::Other(format!("compaction verified_ops delete: {e}")))?;
    Ok((deleted, bytes as u64, floor))
}

fn trim_upsert_head_payloads(
    conn: &rusqlite::Connection,
    placeholders: &str,
    ids: &[Vec<u8>],
) -> Result<(), GCError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT heads.store_id, heads.table_name, heads.row_pk, heads.payload
             FROM oplog_db.oplog AS o
             JOIN oplog_db.oplog_heads AS heads
               ON heads.store_id = o.store_id
              AND heads.table_name = o.table_name
              AND heads.row_pk = o.row_pk
              AND heads.op_id = o.op_id
             WHERE o.op_id IN ({placeholders})
               AND +o.store_id = 'proxydb'
               AND LENGTH(heads.payload) > 0"
        ))
        .map_err(|e| GCError::Other(format!("compaction head trim select prepare: {e}")))?;
    let rows = stmt
        .query_map(params_from_iter(ids.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|e| GCError::Other(format!("compaction head trim select: {e}")))?;
    let mut clear_stmt = conn
        .prepare_cached(
            "UPDATE oplog_db.oplog_heads
             SET payload = X''
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .map_err(|e| GCError::Other(format!("compaction head trim update prepare: {e}")))?;
    for row in rows {
        let (store_id, table_name, row_pk, payload) =
            row.map_err(|e| GCError::Other(format!("compaction head trim row: {e}")))?;
        if !SELF_DRAINING_TABLES.contains(&table_name.as_str()) {
            continue;
        }
        if let Ok(decoded) = crate::row_op::ProxyDbOp::decode_bytes(&payload) {
            if matches!(decoded.mutation, crate::row_op::Mutation::Upsert { .. }) {
                clear_stmt
                    .execute(params![store_id, table_name, row_pk])
                    .map_err(|e| GCError::Other(format!("compaction head trim update: {e}")))?;
            }
        }
    }
    Ok(())
}
