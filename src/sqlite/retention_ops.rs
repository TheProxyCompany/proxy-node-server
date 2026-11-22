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

/// Pin clauses shared by the three per-chunk statements in
/// `delete_ops_subchunk`: graph edges, undispatched Move callbacks, queued
/// proxydb projections, and the proxy.db replay queue. The replay-queue leg
/// must stay a correlated `NOT EXISTS`: `state != 'failed'` cannot use
/// `idx_external_row_replay_state`, so `NOT IN` plans as a full-table LIST
/// SUBQUERY per statement (three scans of an 8.2M-row queue per 500-op chunk
/// on the live fleet; proxy-node-server#21).
const CHUNK_PINS: &str = "NOT IN (SELECT edge_op_id FROM oplog_db.pending_graph_edges)
            AND {alias}.op_id NOT IN
                (SELECT resolution_op_id FROM oplog_db.move_callback_fires WHERE dispatched = 0)
            AND {alias}.op_id NOT IN
                (SELECT op_id FROM oplog_db.proxydb_projection_queue)
            AND NOT EXISTS (SELECT 1 FROM external_row_replay_queue AS rq
                            WHERE rq.op_id = {alias}.op_id AND rq.state != 'failed')";

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
    let pins = CHUNK_PINS;
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
#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal schema with the exact production DDL (read live 2026-11-22):
    /// the main database carries `external_row_replay_queue` (grand-central
    /// migration v105; `op_id BLOB NOT NULL UNIQUE` yields
    /// `sqlite_autoindex_external_row_replay_queue_1` for the pin probe);
    /// `oplog_db` carries the mesh tables `delete_ops_chunk` touches.
    fn replay_test_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("ATTACH ':memory:' AS oplog_db").unwrap();
        conn.execute_batch(
            "CREATE TABLE external_row_replay_queue (
                replay_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                op_id       BLOB NOT NULL UNIQUE,
                envelope    BLOB NOT NULL,
                origin      INTEGER NOT NULL CHECK (origin IN (0, 1)),
                attempts    INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                state       TEXT NOT NULL DEFAULT 'pending'
                            CHECK (state IN ('pending', 'covered', 'failed')),
                retry_at    INTEGER NOT NULL DEFAULT 0,
                last_error  TEXT,
                queued_at   TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE INDEX idx_external_row_replay_state
                ON external_row_replay_queue(state, replay_id);
            CREATE TABLE oplog_db.oplog (
                op_id        BLOB PRIMARY KEY,
                hlc          INTEGER NOT NULL,
                device_id    BLOB NOT NULL,
                store_id     TEXT NOT NULL,
                payload      BLOB NOT NULL,
                envelope     BLOB NOT NULL,
                table_name   TEXT NOT NULL,
                row_pk       TEXT NOT NULL,
                origin       INTEGER NOT NULL,
                applied      INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE oplog_db.oplog_arrivals (
                relay_seq  INTEGER PRIMARY KEY AUTOINCREMENT,
                op_id      BLOB NOT NULL UNIQUE REFERENCES oplog(op_id) ON DELETE CASCADE,
                arrived_at INTEGER NOT NULL
            );
            CREATE TABLE oplog_db.mesh_relay_state (
                singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
                stream_epoch          BLOB NOT NULL CHECK (length(stream_epoch) = 32),
                compacted_through_seq INTEGER NOT NULL DEFAULT 0 CHECK (compacted_through_seq >= 0)
            );
            CREATE TABLE oplog_db.pending_graph_edges (
                endpoint_id TEXT NOT NULL,
                edge_op_id  BLOB NOT NULL,
                PRIMARY KEY (endpoint_id, edge_op_id)
            );
            CREATE TABLE oplog_db.move_callback_fires (
                move_id          TEXT PRIMARY KEY,
                resolution_op_id BLOB NOT NULL,
                fired_at         TEXT NOT NULL,
                dispatched       INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE oplog_db.proxydb_projection_queue (
                projection_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                op_id           BLOB NOT NULL UNIQUE REFERENCES oplog(op_id) ON DELETE CASCADE
            );
            CREATE TABLE oplog_db.oplog_heads (
                store_id      TEXT NOT NULL,
                table_name    TEXT NOT NULL,
                row_pk        TEXT NOT NULL,
                hlc           INTEGER NOT NULL,
                device_id     BLOB NOT NULL,
                op_id         BLOB NOT NULL,
                payload       BLOB NOT NULL,
                origin_device BLOB,
                PRIMARY KEY (store_id, table_name, row_pk)
            );
            CREATE TABLE oplog_db.mesh_verified_ops (
                op_id            BLOB PRIMARY KEY REFERENCES oplog(op_id) ON DELETE CASCADE,
                envelope_sha256  BLOB NOT NULL CHECK (length(envelope_sha256) = 32)
            );",
        )
        .unwrap();
        conn
    }

    fn seed_op(conn: &rusqlite::Connection, tag: u8) -> OpId {
        let op_id = OpId::from_bytes([tag; 32]);
        conn.execute(
            "INSERT INTO oplog_db.oplog
             (op_id, hlc, device_id, store_id, payload, envelope, table_name, row_pk, origin, applied)
             VALUES (?1, 1, ?2, 'mesh', X'00', X'00', 'nodes', ?3, 0, 1)",
            params![op_id.as_bytes().to_vec(), vec![7u8; 32], format!("row-{tag}")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oplog_db.oplog_arrivals (op_id, arrived_at) VALUES (?1, 1)",
            params![op_id.as_bytes().to_vec()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oplog_db.mesh_verified_ops (op_id, envelope_sha256) VALUES (?1, ?2)",
            params![op_id.as_bytes().to_vec(), vec![3u8; 32]],
        )
        .unwrap();
        op_id
    }

    fn surviving_oplog_ids(conn: &rusqlite::Connection) -> Vec<Vec<u8>> {
        let mut stmt = conn
            .prepare("SELECT op_id FROM oplog_db.oplog ORDER BY op_id")
            .unwrap();
        stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// pns#21 regression, behavioral leg: a chunk handed DIRECTLY to
    /// `delete_ops_chunk` must keep every op still pinned in the proxy.db
    /// replay queue. The scan phase pre-filters pinned ops
    /// (`compaction_candidates`), so end-to-end compaction tests never reach
    /// this guard and pass even with it neutralized; only a direct chunk with
    /// a pinned id exercises it. Neutralizing the pin (`AND 1 = 1`) must fail
    /// this test.
    #[test]
    fn delete_ops_chunk_keeps_ops_pinned_in_replay_queue() {
        let conn = replay_test_conn();
        conn.execute(
            "INSERT INTO oplog_db.mesh_relay_state (singleton, stream_epoch, compacted_through_seq)
             VALUES (1, ?1, 0)",
            params![vec![9u8; 32]],
        )
        .unwrap();
        let pending = seed_op(&conn, 0xA1);
        let covered = seed_op(&conn, 0xB2);
        let failed = seed_op(&conn, 0xC3);
        let unpinned = seed_op(&conn, 0xD4);
        for (op_id, state) in [
            (&pending, "pending"),
            (&covered, "covered"),
            (&failed, "failed"),
        ] {
            conn.execute(
                "INSERT INTO external_row_replay_queue (op_id, envelope, origin, state, queued_at, updated_at)
                 VALUES (?1, X'00', 0, ?2, 't', 't')",
                params![op_id.as_bytes().to_vec(), state],
            )
            .unwrap();
        }

        let (deleted, _bytes) = delete_ops_chunk(
            &conn,
            &[(pending, 1), (covered, 2), (failed, 3), (unpinned, 4)],
        )
        .unwrap();

        assert_eq!(deleted, 2, "only the failed and unpinned ops may delete");
        assert_eq!(
            surviving_oplog_ids(&conn),
            vec![pending.as_bytes().to_vec(), covered.as_bytes().to_vec()],
            "pending and covered replay rows must keep their ops",
        );
        let arrivals_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM oplog_db.oplog_arrivals", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(arrivals_left, 2, "pinned arrivals survive");
        let verified_left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM oplog_db.mesh_verified_ops",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(verified_left, 2, "verified markers follow their ops");
        let floor: i64 = conn
            .query_row(
                "SELECT compacted_through_seq FROM oplog_db.mesh_relay_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(floor, 4, "floor advances past the deleted arrivals only");
    }

    /// pns#21 regression, plan leg: the replay-queue pin must compile to an
    /// index probe, never a full scan of `external_row_replay_queue` (the
    /// NOT IN form materializes all 8.2M queued rows into a LIST SUBQUERY
    /// plus bloom filter, three times per 500-op chunk; the live 110-190 s
    /// writer holds). Reverting `CHUNK_PINS` to NOT IN keeps the behavioral
    /// test green (the semantics match) and must fail this test, so the
    /// performance property is pinned too. The sibling pin tables
    /// (`pending_graph_edges`, `move_callback_fires`; 4 and 102 rows live)
    /// intentionally plan as small LIST SUBQUERY scans and are not covered
    /// by these assertions. The head-pin text below mirrors
    /// `delete_ops_subchunk`; the clause under test comes from `CHUNK_PINS`
    /// itself so it cannot drift from production.
    #[test]
    fn replay_queue_pin_plans_as_index_probe_not_list_subquery() {
        let conn = replay_test_conn();
        let oplog_pins = CHUNK_PINS.replace("{alias}", "oplog");
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
        let sql = format!(
            "EXPLAIN QUERY PLAN
             DELETE FROM oplog_db.oplog
             WHERE op_id IN (?1, ?2, ?3, ?4) AND oplog.op_id {oplog_pins}
               AND {oplog_head_pin}"
        );
        let ids: Vec<Vec<u8>> = (0u8..4).map(|b| vec![b; 32]).collect();
        let mut stmt = conn.prepare(&sql).unwrap();
        let plan = stmt
            .query_map(params_from_iter(ids.iter()), |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        assert!(
            plan.contains(
                "SEARCH rq USING INDEX sqlite_autoindex_external_row_replay_queue_1 (op_id=?)"
            ),
            "pin must probe the replay queue's op_id unique index:\n{plan}"
        );
        assert!(
            !plan.contains("SCAN external_row_replay_queue") && !plan.contains("SCAN rq\n"),
            "pin must never scan the replay queue (NOT IN materializes all 8.2M rows):\n{plan}"
        );
    }
}
