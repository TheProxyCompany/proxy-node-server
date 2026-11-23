//! Candidate scanning (horizon + recent LWW) and bounded chunked deletion over
//! `oplog_db`.

use crate::OpId;
use rusqlite::{params, params_from_iter};

use super::SqliteError as GCError;
use super::retention::{CompactionPolicy, DELETE_CHUNK};
pub use super::retention_orphan::{OrphanOplogScan, orphan_oplog_candidates};
use super::retention_pins::{
    PinState, PinTables, chunk_pin_clauses, is_candidate_pinned, oplog_index_exists,
    oplog_table_exists, store_head_op_ids, trim_upsert_head_payloads,
};

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
        Ok(if oplog_index_exists(conn, "idx_oplog_applied")? {
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
    oplog_table_exists(conn, name)
}

pub fn compaction_candidates(
    conn: &rusqlite::Connection,
    policy: &CompactionPolicy,
    safe_floor: i64,
    deadline: std::time::Instant,
    resume_after: i64,
    probe_index: CompactionProbeIndex,
) -> Result<CompactionScan, GCError> {
    compaction_candidates_with_lww(
        conn,
        policy,
        safe_floor,
        safe_floor,
        deadline,
        resume_after,
        probe_index,
    )
}

/// Scan `oplog_arrivals` up to `lww_floor` (`>= safe_floor`).
///
/// - Arrivals at or below `safe_floor` (`min(ack_floor, horizon_floor)`) undergo
///   true horizon pruning: every `applied = 1`, unpinned op deletes even when it
///   is the sole, earliest, or latest op for its `(store_id, table_name, row_pk)`
///   (preserving only one highest-HLC watermark anchor per store).
/// - Arrivals in `(safe_floor, lww_floor]` (within the 7-day window, already
///   acked by active peers) shed superseded LWW overwrites while keeping each
///   row's live head, `keep_per_row` window, and earliest op.
pub fn compaction_candidates_with_lww(
    conn: &rusqlite::Connection,
    policy: &CompactionPolicy,
    safe_floor: i64,
    lww_floor: i64,
    deadline: std::time::Instant,
    resume_after: i64,
    probe_index: CompactionProbeIndex,
) -> Result<CompactionScan, GCError> {
    let ceiling = safe_floor.max(lww_floor);
    if ceiling <= 0 {
        return Ok(CompactionScan {
            candidates: Vec::new(),
            next_cursor: 0,
            scanned: 0,
        });
    }
    let head: i64 = conn
        .prepare_cached("SELECT COALESCE(MAX(relay_seq), 0) FROM oplog_db.oplog_arrivals")
        .map_err(|e| GCError::Other(format!("compaction head prepare: {e}")))?
        .query_row([], |row| row.get(0))
        .map_err(|e| GCError::Other(format!("compaction head: {e}")))?;

    let pins = PinState::detect(conn)?;
    let store_heads = store_head_op_ids(conn, &pins.tables)?;
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
    let mut head_pin = conn
        .prepare_cached(
            "SELECT 1 FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND op_id = ?4
             LIMIT 1",
        )
        .map_err(|e| GCError::Other(format!("compaction head pin prepare: {e}")))?;

    const SCAN_PAGE: usize = 2048;
    const LEGACY_LWW_SCAN_CAP: usize = 16_384;
    let scan_cap = if matches!(probe_index, CompactionProbeIndex::LegacyLww) {
        policy.candidate_scan_cap.min(LEGACY_LWW_SCAN_CAP)
    } else {
        policy.candidate_scan_cap.max(SCAN_PAGE)
    };
    let mut candidates = Vec::new();
    let mut scanned = 0usize;
    let initial_resume = resume_after.max(0).min(ceiling);
    let mut after_seq = initial_resume;
    let upper_bound = ceiling;
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
                params![after_seq, upper_bound, head, SCAN_PAGE as i64],
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
            let Ok(op_arr) = <[u8; 32]>::try_from(op_id.as_slice()) else {
                continue;
            };
            if store_heads.contains(&op_arr) {
                continue;
            }
            let horizon_eligible = relay_seq <= safe_floor;
            if !horizon_eligible {
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
                if head_pin
                    .exists(params![store, table, row_pk, op_id])
                    .map_err(|e| GCError::Other(format!("compaction head probe: {e}")))?
                {
                    continue;
                }
            }
            if is_candidate_pinned(conn, &pins, &op_id, &store, &table, &row_pk)? {
                continue;
            }
            candidates.push((OpId::from_bytes(op_arr), relay_seq));
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
    delete_ops_chunk_with_floor(conn, chunk, i64::MAX)
}

pub fn delete_ops_chunk_with_floor(
    conn: &rusqlite::Connection,
    chunk: &[(OpId, i64)],
    horizon_floor: i64,
) -> Result<(usize, u64), GCError> {
    if chunk.is_empty() {
        return Ok((0, 0));
    }
    let tables = PinTables::detect(conn)?;
    let store_heads = store_head_op_ids(conn, &tables)?;
    let mut total_deleted = 0usize;
    let mut total_bytes = 0u64;
    let mut max_floor = 0i64;
    for sub in chunk.chunks(DELETE_CHUNK) {
        let mut horizon_ids = Vec::new();
        let mut lww_ids = Vec::new();
        for (op_id, seq) in sub {
            if store_heads.contains(op_id.as_bytes()) {
                continue;
            }
            if *seq <= horizon_floor {
                horizon_ids.push(op_id.as_bytes().to_vec());
            } else {
                lww_ids.push(op_id.as_bytes().to_vec());
            }
        }
        for (ids, protect_head) in [(&horizon_ids, false), (&lww_ids, true)] {
            if ids.is_empty() {
                continue;
            }
            let (deleted, bytes, floor) = delete_ops_ids(conn, ids, &tables, protect_head)?;
            total_deleted += deleted;
            total_bytes += bytes;
            if deleted > 0 {
                max_floor = max_floor.max(floor);
            }
        }
    }
    if total_deleted > 0 && max_floor > 0 {
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

pub(crate) fn delete_ops_ids(
    conn: &rusqlite::Connection,
    ids: &[Vec<u8>],
    tables: &PinTables,
    protect_head: bool,
) -> Result<(usize, u64, i64), GCError> {
    let placeholders = (0..ids.len())
        .map(|i| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let oplog_pins = chunk_pin_clauses(tables, "oplog", true);
    let arrival_pins = chunk_pin_clauses(tables, "oplog_arrivals", false);
    let oplog_head_guard = if protect_head && oplog_table_exists(conn, "oplog_heads")? {
        "AND NOT EXISTS (
             SELECT 1 FROM oplog_db.oplog_heads AS heads
             WHERE heads.store_id = oplog.store_id
               AND heads.table_name = oplog.table_name
               AND heads.row_pk = oplog.row_pk
               AND heads.op_id = oplog.op_id
         )"
    } else {
        ""
    };
    let arrival_head_guard = if protect_head && oplog_table_exists(conn, "oplog_heads")? {
        "AND NOT EXISTS (
             SELECT 1
             FROM oplog_db.oplog AS pinned_op
             JOIN oplog_db.oplog_heads AS heads
               ON heads.store_id = pinned_op.store_id
              AND heads.table_name = pinned_op.table_name
              AND heads.row_pk = pinned_op.row_pk
              AND heads.op_id = pinned_op.op_id
             WHERE pinned_op.op_id = oplog_arrivals.op_id
         )"
    } else {
        ""
    };

    let (bytes, floor): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COALESCE(SUM(LENGTH(oplog.envelope) + LENGTH(oplog.payload)), 0),
                        COALESCE(MAX(arrivals.relay_seq), 0)
                 FROM oplog_db.oplog
                 LEFT JOIN oplog_db.oplog_arrivals AS arrivals ON arrivals.op_id = oplog.op_id
                 WHERE oplog.op_id IN ({placeholders})
                   AND {oplog_pins}
                   {oplog_head_guard}"
            ),
            params_from_iter(ids.iter()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| GCError::Other(format!("compaction chunk stats: {e}")))?;
    if !protect_head {
        trim_upsert_head_payloads(conn, &placeholders, ids)?;
    }
    if oplog_table_exists(conn, "oplog_arrivals")? {
        conn.execute(
            &format!(
                "DELETE FROM oplog_db.oplog_arrivals
                 WHERE op_id IN ({placeholders})
                   AND {arrival_pins}
                   {arrival_head_guard}"
            ),
            params_from_iter(ids.iter()),
        )
        .map_err(|e| GCError::Other(format!("compaction arrival delete: {e}")))?;
    }
    let deleted = conn
        .execute(
            &format!(
                "DELETE FROM oplog_db.oplog
                 WHERE op_id IN ({placeholders})
                   AND {oplog_pins}
                   {oplog_head_guard}"
            ),
            params_from_iter(ids.iter()),
        )
        .map_err(|e| GCError::Other(format!("compaction oplog delete: {e}")))?;
    if tables.mesh_verified_ops {
        let quarantine_guard = if tables.mesh_unverified_ops {
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
    }
    Ok((deleted, bytes as u64, floor))
}
