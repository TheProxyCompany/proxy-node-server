//! Move callback outbox ledger and durable pending-edge / endpoint-wake queue queries in `oplog.db`.

use crate::OpId;
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;

/// Record that a move's callbacks are owed on this device, keyed on the **move id**
/// (a move resolves once, so the outbox holds one row per move). `resolution_op_id`
/// names the op whose image carries the resolved blocks/response to dispatch. The
/// row is written undispatched (`dispatched = 0`) inside the same transaction that
/// logs the triggering op. `INSERT OR IGNORE` makes it idempotent — only the first
/// fire for a move returns `true`; every re-derivation under replay yields `false`.
pub fn record_move_callback_fire(
    conn: &rusqlite::Connection,
    move_id: &str,
    resolution_op_id: &OpId,
) -> Result<bool, GCError> {
    let now = chrono::Utc::now().to_rfc3339();
    let changed = conn
        .execute(
            "INSERT OR IGNORE INTO oplog_db.move_callback_fires
                (move_id, resolution_op_id, fired_at, dispatched)
             VALUES (?1, ?2, ?3, 0)",
            params![move_id, resolution_op_id.as_bytes().as_slice(), now],
        )
        .map_err(|e| GCError::Other(format!("record move callback fire: {e}")))?;
    Ok(changed > 0)
}

/// Whether a fire ledger row exists for this move at all (dispatched or not).
/// Checked FIRST by the gate: once a move has fired anywhere on this device,
/// every later re-derivation — proven, unproven, or replayed — is a Skip.
pub fn move_callback_recorded(conn: &rusqlite::Connection, move_id: &str) -> Result<bool, GCError> {
    conn.query_row(
        "SELECT 1 FROM oplog_db.move_callback_fires WHERE move_id = ?1",
        params![move_id],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
    .map_err(|e| GCError::Other(format!("move callback recorded: {e}")))
}

/// The resolution op id of a move's outbox row iff it is still undispatched, else
/// `None`. The per-move dispatch path reads it after commit to load the image to run.
pub fn undispatched_move_callback(
    conn: &rusqlite::Connection,
    move_id: &str,
) -> Result<Option<OpId>, GCError> {
    conn.query_row(
        "SELECT resolution_op_id FROM oplog_db.move_callback_fires
         WHERE move_id = ?1 AND dispatched = 0",
        params![move_id],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(|e| GCError::Other(format!("undispatched move callback: {e}")))?
    .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
    .map(OpId::from_bytes)
    .map(Ok)
    .transpose()
}

/// Every undispatched outbox row as `(move_id, resolution_op_id)`. The startup
/// drain re-delivers these — fires recorded before a crash that landed between the
/// commit and the dispatch.
pub fn undispatched_move_callbacks(
    conn: &rusqlite::Connection,
) -> Result<Vec<(String, OpId)>, GCError> {
    let mut stmt = conn
        .prepare("SELECT move_id, resolution_op_id FROM oplog_db.move_callback_fires WHERE dispatched = 0")
        .map_err(|e| GCError::Other(format!("undispatched move callbacks prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| GCError::Other(format!("undispatched move callbacks query: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        let (move_id, op_id) =
            row.map_err(|e| GCError::Other(format!("undispatched move callbacks row: {e}")))?;
        if let Ok(arr) = <[u8; 32]>::try_from(op_id.as_slice()) {
            out.push((move_id, OpId::from_bytes(arr)));
        }
    }
    Ok(out)
}

/// Cancel only the still-undispatched image the caller checked. A newer
/// approval or an already delivered action keeps its ledger row.
pub fn discard_undispatched_move_callback(
    conn: &rusqlite::Connection,
    move_id: &str,
    resolution: &OpId,
) -> Result<(), GCError> {
    conn.execute(
        "DELETE FROM oplog_db.move_callback_fires WHERE move_id = ?1 AND resolution_op_id = ?2 AND dispatched = 0",
        params![move_id, resolution.as_bytes().as_slice()],
    ).map_err(|error| GCError::Other(format!("discard nonterminal Move callback: {error}")))?;
    Ok(())
}

/// Mark a move's outbox row dispatched once its callbacks have been delivered, so
/// the startup drain does not re-run it. Left at 0 by a crash before this call —
/// the accepted rare-duplicate window.
pub fn mark_move_callback_dispatched(
    conn: &rusqlite::Connection,
    move_id: &str,
) -> Result<(), GCError> {
    conn.execute(
        "UPDATE oplog_db.move_callback_fires SET dispatched = 1 WHERE move_id = ?1",
        params![move_id],
    )
    .map_err(|e| GCError::Other(format!("mark move callback dispatched: {e}")))?;
    Ok(())
}

/// Buffer an edge op against a missing endpoint (P3-D6). Written in the same
/// proxy.db transaction as the oplog append so the pending set is crash-consistent
/// with the log. `INSERT OR IGNORE` keeps re-buffering the same edge idempotent.
pub fn buffer_pending_edge(
    conn: &rusqlite::Connection,
    endpoint_id: &str,
    edge_op_id: &OpId,
) -> Result<(), GCError> {
    conn.execute(
        "INSERT OR IGNORE INTO oplog_db.pending_graph_edges (endpoint_id, edge_op_id) VALUES (?1, ?2)",
        params![endpoint_id, edge_op_id.as_bytes().as_slice()],
    )
    .map_err(|e| GCError::Other(format!("buffer pending edge: {e}")))?;
    Ok(())
}

pub struct PendingEdgePage {
    pub ids: Vec<OpId>,
    pub quarantined: usize,
}

/// Edge op ids buffered on an endpoint, one bounded page at a time. Malformed
/// ids are moved to a durable failure table in the caller's transaction so they
/// count as progress and can never pin a wake at the head of the queue.
pub fn pending_edges_for(
    conn: &rusqlite::Connection,
    endpoint_id: &str,
    limit: usize,
) -> Result<PendingEdgePage, GCError> {
    let mut stmt = conn
        .prepare(
            "SELECT edge_op_id FROM oplog_db.pending_graph_edges
             WHERE endpoint_id = ?1
             ORDER BY edge_op_id
             LIMIT ?2",
        )
        .map_err(|e| GCError::Other(format!("pending edges prepare: {e}")))?;
    let rows = stmt
        .query_map(params![endpoint_id, limit as i64], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|e| GCError::Other(format!("pending edges query: {e}")))?;
    let mut ids = Vec::new();
    let mut malformed = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| GCError::Other(format!("pending edges row: {e}")))?;
        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
            ids.push(OpId::from_bytes(arr));
        } else {
            malformed.push(bytes);
        }
    }
    drop(stmt);

    for edge_op_id in &malformed {
        conn.execute(
            "INSERT INTO oplog_db.pending_graph_edge_failures (
                 endpoint_id, edge_op_id, last_error, failed_at
             ) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(endpoint_id, edge_op_id) DO UPDATE SET
                 last_error = excluded.last_error,
                 failed_at = excluded.failed_at",
            params![
                endpoint_id,
                edge_op_id,
                format!("invalid op id length {}; expected 32", edge_op_id.len())
            ],
        )
        .map_err(|error| GCError::Other(format!("quarantine pending edge: {error}")))?;
        conn.execute(
            "DELETE FROM oplog_db.pending_graph_edges
             WHERE endpoint_id = ?1 AND edge_op_id = ?2",
            params![endpoint_id, edge_op_id],
        )
        .map_err(|error| GCError::Other(format!("retire malformed pending edge: {error}")))?;
        eprintln!(
            "proxy-node-server: quarantined malformed pending edge id endpoint_id={endpoint_id} bytes={}",
            edge_op_id.len()
        );
    }
    Ok(PendingEdgePage {
        ids,
        quarantined: malformed.len(),
    })
}

/// Queue a live endpoint for paged pending-edge activation. The pending edge
/// rows are already durable; this compact unique ticket prevents dead/tombstoned
/// endpoints from occupying the worker's scan prefix and survives a crash
/// between the node commit and the first fanout page.
pub fn queue_pending_edge_wake(
    conn: &rusqlite::Connection,
    endpoint_id: &str,
) -> Result<(), GCError> {
    conn.execute(
        "INSERT OR IGNORE INTO oplog_db.pending_graph_endpoint_wakes (
             endpoint_id, queued_at
         )
         SELECT ?1, datetime('now')
         WHERE EXISTS (
             SELECT 1 FROM oplog_db.pending_graph_edges
             WHERE endpoint_id = ?1
         )",
        params![endpoint_id],
    )
    .map(|_| ())
    .map_err(|e| GCError::Other(format!("queue pending graph endpoint wake: {e}")))
}

pub fn pending_edge_wake(
    conn: &rusqlite::Connection,
    endpoint_id: Option<&str>,
) -> Result<Option<(i64, String)>, GCError> {
    let sql = if endpoint_id.is_some() {
        "SELECT wake_id, endpoint_id
         FROM oplog_db.pending_graph_endpoint_wakes
         WHERE endpoint_id = ?1
         LIMIT 1"
    } else {
        "SELECT wake_id, endpoint_id
         FROM oplog_db.pending_graph_endpoint_wakes
         ORDER BY wake_id
         LIMIT 1"
    };
    let mut stmt = conn
        .prepare_cached(sql)
        .map_err(|e| GCError::Other(format!("prepare pending graph endpoint wake: {e}")))?;
    let row = if let Some(endpoint_id) = endpoint_id {
        stmt.query_row(params![endpoint_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
    } else {
        stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
    };
    row.map_err(|e| GCError::Other(format!("read pending graph endpoint wake: {e}")))
}

pub fn remove_pending_edge_wake(conn: &rusqlite::Connection, wake_id: i64) -> Result<(), GCError> {
    conn.execute(
        "DELETE FROM oplog_db.pending_graph_endpoint_wakes WHERE wake_id = ?1",
        params![wake_id],
    )
    .map(|_| ())
    .map_err(|e| GCError::Other(format!("remove pending graph endpoint wake: {e}")))
}

/// Move a partially drained endpoint to the tail of the durable wake queue.
/// Rotation commits with the page retirement, so every live endpoint receives
/// one bounded page per round without a second cursor table.
pub fn rotate_pending_edge_wake(
    conn: &rusqlite::Connection,
    wake_id: i64,
    endpoint_id: &str,
) -> Result<(), GCError> {
    let deleted = conn
        .execute(
            "DELETE FROM oplog_db.pending_graph_endpoint_wakes WHERE wake_id = ?1",
            params![wake_id],
        )
        .map_err(|error| GCError::Other(format!("rotate pending graph endpoint wake: {error}")))?;
    if deleted != 1 {
        return Err(GCError::Other(format!(
            "rotate pending graph endpoint wake: expected wake {wake_id} to exist"
        )));
    }
    conn.execute(
        "INSERT INTO oplog_db.pending_graph_endpoint_wakes (endpoint_id, queued_at)
         VALUES (?1, datetime('now'))",
        params![endpoint_id],
    )
    .map(|_| ())
    .map_err(|error| GCError::Other(format!("requeue pending graph endpoint wake: {error}")))
}

pub fn pending_edges_remain(
    conn: &rusqlite::Connection,
    endpoint_id: &str,
) -> Result<bool, GCError> {
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM oplog_db.pending_graph_edges
             WHERE endpoint_id = ?1
         )",
        params![endpoint_id],
        |row| row.get(0),
    )
    .map_err(|e| GCError::Other(format!("probe pending graph edges: {e}")))
}

/// Drop one `(endpoint, edge)` buffer entry once that endpoint no longer blocks
/// the edge (its other endpoint may still hold a separate entry).
pub fn remove_pending_edge(
    conn: &rusqlite::Connection,
    endpoint_id: &str,
    edge_op_id: &OpId,
) -> Result<(), GCError> {
    conn.execute(
        "DELETE FROM oplog_db.pending_graph_edges WHERE endpoint_id = ?1 AND edge_op_id = ?2",
        params![endpoint_id, edge_op_id.as_bytes().as_slice()],
    )
    .map_err(|e| GCError::Other(format!("remove pending edge: {e}")))?;
    Ok(())
}

/// Drop every buffer entry for an edge op across both endpoints — used when the
/// edge resolves (both endpoints live) or a newer edge write supersedes it.
pub fn remove_pending_edge_all(
    conn: &rusqlite::Connection,
    edge_op_id: &OpId,
) -> Result<(), GCError> {
    conn.execute(
        "DELETE FROM oplog_db.pending_graph_edges WHERE edge_op_id = ?1",
        params![edge_op_id.as_bytes().as_slice()],
    )
    .map_err(|e| GCError::Other(format!("remove pending edge all: {e}")))?;
    Ok(())
}

/// Drop every pending buffer entry for an edge *row* — the buffered upserts of one
/// edge id on either endpoint, found by joining the buffer's `edge_op_id` back to
/// that edge row's ops in the log. Used when a `DeleteEdge` wins LWW over the row
/// (P3-D6): its shadowed pending upserts can never attach, so their durable intents
/// are cleared rather than left to strand on an endpoint that never resurrects.
pub fn remove_pending_edges_for_edge_row(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    edge_row_pk: &str,
) -> Result<(), GCError> {
    conn.execute(
        "DELETE FROM oplog_db.pending_graph_edges
         WHERE edge_op_id IN (
             SELECT op_id FROM oplog_db.oplog
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
         )",
        params![store, table, edge_row_pk],
    )
    .map_err(|e| GCError::Other(format!("remove pending edges for edge row: {e}")))?;
    Ok(())
}
