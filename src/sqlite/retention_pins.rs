//! Pin probes, store high-water-mark anchors, and head-payload trimming for
//! `oplog_db` horizon compaction.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, params, params_from_iter};

use super::SqliteError as GCError;

/// Bulk `proxydb` tables whose `oplog_heads.payload` may be trimmed to `X''`
/// on `Mutation::Upsert` once their `oplog` row is pruned. Readers treat an
/// empty head payload on these tables as a covered upsert (`RowDivergence::Covered`),
/// while `Mutation::Delete` tombstones and smaller config/manifest tables keep
/// their full head payload.
const HEAD_PAYLOAD_TRIM_TABLES: &[&str] = &[
    "items",
    "sequences",
    "conversation_jobs",
    "message_attachments",
    "party_reactions",
    "external_thread_send_receipts",
    "worksite_metadata",
];

#[derive(Clone, Copy)]
pub(crate) struct PinTables {
    pub pending_graph_edges: bool,
    pub move_callback_fires: bool,
    pub proxydb_projection_queue: bool,
    pub external_row_pending_ops: bool,
    pub external_row_pending_dependencies: bool,
    pub trellis_projection_failures: bool,
    pub external_row_replay_queue: bool,
    pub mesh_verified_ops: bool,
    pub mesh_unverified_ops: bool,
    pub idx_oplog_store: bool,
    pub idx_oplog_order: bool,
    pub idx_oplog_lww: bool,
}

impl PinTables {
    pub fn detect(conn: &rusqlite::Connection) -> Result<Self, GCError> {
        Ok(Self {
            pending_graph_edges: oplog_table_exists(conn, "pending_graph_edges")?,
            move_callback_fires: oplog_table_exists(conn, "move_callback_fires")?,
            proxydb_projection_queue: oplog_table_exists(conn, "proxydb_projection_queue")?,
            external_row_pending_ops: oplog_table_exists(conn, "external_row_pending_ops")?,
            external_row_pending_dependencies: oplog_table_exists(
                conn,
                "external_row_pending_dependencies",
            )?,
            trellis_projection_failures: oplog_table_exists(conn, "trellis_projection_failures")?,
            external_row_replay_queue: main_table_exists(conn, "external_row_replay_queue")?,
            mesh_verified_ops: oplog_table_exists(conn, "mesh_verified_ops")?,
            mesh_unverified_ops: oplog_table_exists(conn, "mesh_unverified_ops")?,
            idx_oplog_store: oplog_index_exists(conn, "idx_oplog_store")?,
            idx_oplog_order: oplog_index_exists(conn, "idx_oplog_order")?,
            idx_oplog_lww: oplog_index_exists(conn, "idx_oplog_lww")?,
        })
    }
}

pub(crate) fn oplog_table_exists(conn: &rusqlite::Connection, name: &str) -> Result<bool, GCError> {
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

fn main_table_exists(conn: &rusqlite::Connection, name: &str) -> Result<bool, GCError> {
    conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM main.sqlite_master
            WHERE type = 'table' AND name = ?1
         )",
        params![name],
        |row| row.get(0),
    )
    .map_err(|e| GCError::Other(format!("probe main table {name}: {e}")))
}

pub(crate) fn oplog_index_exists(conn: &rusqlite::Connection, name: &str) -> Result<bool, GCError> {
    conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM oplog_db.sqlite_master
            WHERE type = 'index' AND name = ?1
         )",
        params![name],
        |row| row.get(0),
    )
    .map_err(|e| GCError::Other(format!("probe oplog_db index {name}: {e}")))
}

/// Retain the single highest-order-key applied op per `store_id` in `oplog_db.oplog`
/// so `oplog::head()` (boot clock recovery) and `oplog::head_in_store()` (snapshot
/// watermarks) remain O(1) index seeks even when all older ops are horizon-pruned.
pub(crate) fn store_head_op_ids(
    conn: &rusqlite::Connection,
    tables: &PinTables,
) -> Result<HashSet<[u8; 32]>, GCError> {
    let mut anchors = HashSet::new();
    if tables.idx_oplog_store && tables.idx_oplog_lww {
        let stores: Vec<String> = conn
            .prepare_cached(
                "WITH RECURSIVE s(id) AS (
                     SELECT MIN(store_id) FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                     UNION ALL
                     SELECT (
                         SELECT MIN(store_id) FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                         WHERE store_id > id
                     )
                     FROM s WHERE id IS NOT NULL
                 )
                 SELECT id FROM s WHERE id IS NOT NULL",
            )
            .map_err(|e| GCError::Other(format!("compaction store list prepare: {e}")))?
            .query_map([], |row| row.get(0))
            .map_err(|e| GCError::Other(format!("compaction store list query: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| GCError::Other(format!("compaction store list row: {e}")))?;
        let mut head_stmt = conn
            .prepare_cached(
                "SELECT op_id FROM oplog_db.oplog INDEXED BY idx_oplog_store
                 WHERE store_id = ?1
                 ORDER BY hlc DESC, device_id DESC, op_id DESC
                 LIMIT 1",
            )
            .map_err(|e| GCError::Other(format!("compaction store head prepare: {e}")))?;
        for store in stores {
            let head: Option<Vec<u8>> = head_stmt
                .query_row(params![store], |row| row.get(0))
                .optional()
                .map_err(|e| GCError::Other(format!("compaction store head query: {e}")))?;
            if let Some(bytes) = head.and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok()) {
                anchors.insert(bytes);
            }
        }
    } else if tables.idx_oplog_order {
        let head: Option<Vec<u8>> = conn
            .query_row(
                "SELECT op_id FROM oplog_db.oplog INDEXED BY idx_oplog_order
                 ORDER BY hlc DESC, device_id DESC, op_id DESC
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| GCError::Other(format!("compaction global head query: {e}")))?;
        if let Some(bytes) = head.and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok()) {
            anchors.insert(bytes);
        }
    }
    Ok(anchors)
}

#[derive(Clone, Copy)]
pub(crate) struct PinState {
    pub tables: PinTables,
    pub has_edges: bool,
    pub has_fires: bool,
    pub has_trellis_failures: bool,
}

impl PinState {
    pub fn detect(conn: &rusqlite::Connection) -> Result<Self, GCError> {
        let tables = PinTables::detect(conn)?;
        let has_edges = tables.pending_graph_edges
            && conn
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM oplog_db.pending_graph_edges LIMIT 1)",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| GCError::Other(format!("probe pending_graph_edges: {e}")))?;
        let has_fires = tables.move_callback_fires
            && conn
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM oplog_db.move_callback_fires WHERE dispatched = 0 LIMIT 1)",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| GCError::Other(format!("probe move_callback_fires: {e}")))?;
        let has_trellis_failures = tables.trellis_projection_failures
            && conn
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM oplog_db.trellis_projection_failures LIMIT 1)",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| GCError::Other(format!("probe trellis_projection_failures: {e}")))?;
        Ok(Self {
            tables,
            has_edges,
            has_fires,
            has_trellis_failures,
        })
    }
}

/// Check whether a candidate op is referenced by any pending projection,
/// dependency, callback outbox, replay queue, or Trellis repair row.
pub(crate) fn is_candidate_pinned(
    conn: &rusqlite::Connection,
    pins: &PinState,
    op_id: &[u8],
    store: &str,
    table: &str,
    row_pk: &str,
) -> Result<bool, GCError> {
    let tables = &pins.tables;
    if pins.has_edges
        && conn
            .prepare_cached(
                "SELECT 1 FROM oplog_db.pending_graph_edges WHERE edge_op_id = ?1 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![op_id]))
            .map_err(|e| GCError::Other(format!("compaction edge probe: {e}")))?
    {
        return Ok(true);
    }
    if pins.has_fires
        && conn
            .prepare_cached(
                "SELECT 1 FROM oplog_db.move_callback_fires
                 WHERE dispatched = 0 AND resolution_op_id = ?1 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![op_id]))
            .map_err(|e| GCError::Other(format!("compaction fire probe: {e}")))?
    {
        return Ok(true);
    }
    if tables.proxydb_projection_queue
        && conn
            .prepare_cached(
                "SELECT 1 FROM oplog_db.proxydb_projection_queue WHERE op_id = ?1 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![op_id]))
            .map_err(|e| GCError::Other(format!("compaction projection probe: {e}")))?
    {
        return Ok(true);
    }
    if tables.external_row_pending_ops
        && conn
            .prepare_cached(
                "SELECT 1 FROM oplog_db.external_row_pending_ops WHERE op_id = ?1 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![op_id]))
            .map_err(|e| GCError::Other(format!("compaction pending_ops probe: {e}")))?
    {
        return Ok(true);
    }
    if tables.external_row_pending_dependencies
        && conn
            .prepare_cached(
                "SELECT 1 FROM oplog_db.external_row_pending_dependencies WHERE op_id = ?1 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![op_id]))
            .map_err(|e| GCError::Other(format!("compaction pending_deps probe: {e}")))?
    {
        return Ok(true);
    }
    if tables.external_row_replay_queue
        && conn
            .prepare_cached(
                "SELECT 1 FROM external_row_replay_queue
                 WHERE op_id = ?1 AND state != 'failed' LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![op_id]))
            .map_err(|e| GCError::Other(format!("compaction replay probe: {e}")))?
    {
        return Ok(true);
    }
    if pins.has_trellis_failures
        && store == "trellis"
        && conn
            .prepare_cached(
                "SELECT 1 FROM oplog_db.trellis_projection_failures
                 WHERE table_name = ?1 AND row_pk = ?2 LIMIT 1",
            )
            .and_then(|mut s| s.exists(params![table, row_pk]))
            .map_err(|e| GCError::Other(format!("compaction trellis failure probe: {e}")))?
    {
        return Ok(true);
    }
    Ok(false)
}

/// Correlated index-probe SQL predicates for `oplog` and `oplog_arrivals` chunks.
/// Every large queue uses `NOT EXISTS` over its `op_id` primary/unique index so
/// SQLite never materializes a full-table `LIST SUBQUERY` bloom filter.
pub(crate) fn chunk_pin_clauses(tables: &PinTables, alias: &str, on_oplog: bool) -> String {
    let mut clauses = Vec::new();
    if on_oplog {
        clauses.push(format!("{alias}.applied = 1"));
    } else {
        clauses.push(format!(
            "EXISTS (SELECT 1 FROM oplog_db.oplog AS ao WHERE ao.op_id = {alias}.op_id AND ao.applied = 1)"
        ));
    }
    if tables.pending_graph_edges {
        clauses.push(format!(
            "{alias}.op_id NOT IN (SELECT edge_op_id FROM oplog_db.pending_graph_edges)"
        ));
    }
    if tables.move_callback_fires {
        clauses.push(format!(
            "{alias}.op_id NOT IN (SELECT resolution_op_id FROM oplog_db.move_callback_fires WHERE dispatched = 0)"
        ));
    }
    if tables.proxydb_projection_queue {
        clauses.push(format!(
            "NOT EXISTS (SELECT 1 FROM oplog_db.proxydb_projection_queue AS pq WHERE pq.op_id = {alias}.op_id)"
        ));
    }
    if tables.external_row_pending_ops {
        clauses.push(format!(
            "NOT EXISTS (SELECT 1 FROM oplog_db.external_row_pending_ops AS ep WHERE ep.op_id = {alias}.op_id)"
        ));
    }
    if tables.external_row_pending_dependencies {
        clauses.push(format!(
            "NOT EXISTS (SELECT 1 FROM oplog_db.external_row_pending_dependencies AS ed WHERE ed.op_id = {alias}.op_id)"
        ));
    }
    if tables.external_row_replay_queue {
        clauses.push(format!(
            "NOT EXISTS (SELECT 1 FROM external_row_replay_queue AS rq WHERE rq.op_id = {alias}.op_id AND rq.state != 'failed')"
        ));
    }
    if tables.trellis_projection_failures {
        if on_oplog {
            clauses.push(format!(
                "NOT ({alias}.store_id = 'trellis' AND EXISTS (
                     SELECT 1 FROM oplog_db.trellis_projection_failures AS tpf
                     WHERE tpf.table_name = {alias}.table_name AND tpf.row_pk = {alias}.row_pk
                 ))"
            ));
        } else {
            clauses.push(format!(
                "NOT EXISTS (
                     SELECT 1 FROM oplog_db.oplog AS to_op
                     JOIN oplog_db.trellis_projection_failures AS tpf
                       ON tpf.table_name = to_op.table_name AND tpf.row_pk = to_op.row_pk
                     WHERE to_op.op_id = {alias}.op_id AND +to_op.store_id = 'trellis'
                 )"
            ));
        }
    }
    clauses.join(" AND ")
}

pub(crate) fn trim_upsert_head_payloads(
    conn: &rusqlite::Connection,
    placeholders: &str,
    ids: &[Vec<u8>],
) -> Result<(), GCError> {
    if !oplog_table_exists(conn, "oplog_heads")? {
        return Ok(());
    }
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
        if !HEAD_PAYLOAD_TRIM_TABLES.contains(&table_name.as_str()) {
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
