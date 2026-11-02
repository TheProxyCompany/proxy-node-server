//! Read and cursor queries over `oplog_db.oplog` and `oplog_db.sync_cursors`.

use crate::{DeviceId, OpId, OrderKey, SignedOp};
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;
use super::oplog::order_key_from_row;

pub fn newest_ops_in_store(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pks: &[&str],
) -> Result<std::collections::HashMap<String, Vec<u8>>, GCError> {
    // The heads table holds one applied winner per covered row, so the batch
    // read is a chunked IN over its primary key — no per-row seek into the
    // oplog history for covered rows. A row absent from the heads table is NOT
    // proof it has no applied op: while the background v83 backfill is still
    // filling the table, a row's head may simply not exist yet, so every
    // head-less pks fall back to one windowed historical query per chunk below.
    // Once the durable backfill marker proves complete, a missing head is
    // definitive and the historical fallback is skipped entirely. Rows with
    // no applied op stay absent from the map.
    const CHUNK: usize = 500;
    let mut newest = std::collections::HashMap::with_capacity(row_pks.len());
    for chunk in row_pks.chunks(CHUNK) {
        let placeholders = (0..chunk.len())
            .map(|i| format!("?{}", i + 3))
            .collect::<Vec<_>>()
            .join(", ");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT row_pk, payload FROM oplog_db.oplog_heads
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk IN ({placeholders})"
            ))
            .map_err(|e| GCError::Other(format!("oplog newest_ops_in_store prepare: {e}")))?;
        let params = std::iter::once(&store as &dyn rusqlite::ToSql)
            .chain(std::iter::once(&table as &dyn rusqlite::ToSql))
            .chain(chunk.iter().map(|pk| pk as &dyn rusqlite::ToSql));
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| GCError::Other(format!("oplog newest_ops_in_store query: {e}")))?;
        for row in rows {
            let (row_pk, payload) =
                row.map_err(|e| GCError::Other(format!("oplog newest_ops_in_store row: {e}")))?;
            newest.insert(row_pk, payload);
        }
    }
    Ok(newest)
}

/// The originating device of `(store, table, row_pk)`: the authenticated
/// `device_id` on the *earliest* applied op for that row, in the same total order
/// (`hlc, device_id, op_id`) the LWW winner is read from — only ascending. For a
/// move's node row this is its creation op, so every replica computes the identical
/// origin from replicated state alone, with no persisted `origin` property to
/// diverge. A later `reconcile` re-mint carries a higher HLC and never displaces
/// the true-earliest op, so the origin is stable.
pub fn origin_device(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
) -> Result<Option<DeviceId>, GCError> {
    // Prefer the head's recorded origin: it survives compaction dropping the
    // earliest op. The earliest-op scan remains the fallback for a head row
    // without one (never written by current maintenance, but the column is
    // nullable by design).
    let recorded: Option<Option<Vec<u8>>> = conn
        .prepare_cached(
            "SELECT origin_device FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![store, table, row_pk], |row| row.get(0))
                .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog origin_device head: {e}")))?;
    if let Some(Some(device)) = recorded {
        if let Ok(device) = <[u8; 32]>::try_from(device.as_slice()) {
            return Ok(Some(DeviceId::from_bytes(device)));
        }
    }
    conn.query_row(
        "SELECT device_id FROM oplog_db.oplog INDEXED BY idx_oplog_lww
         WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
         ORDER BY hlc ASC, device_id ASC, op_id ASC
         LIMIT 1",
        params![store, table, row_pk],
        |row| {
            let device: Vec<u8> = row.get(0)?;
            let device = <[u8; 32]>::try_from(device.as_slice()).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "device id".into(),
                )
            })?;
            Ok(DeviceId::from_bytes(device))
        },
    )
    .optional()
    .map_err(|e| GCError::Other(format!("oplog origin_device: {e}")))
}

/// Every applied op for `(store, table, row_pk)` in ascending total order
/// (`hlc, device_id, op_id`), as `(op_id, payload)`. The move-callback gate reads a
/// move's whole node history to find the earliest resolution image and confirm a
/// creation-shaped op precedes it, so its fire decision is a pure function of the
/// log that re-derives identically however out-of-order the ops arrived.
pub fn ops_for_row_asc(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
) -> Result<Vec<(OpId, Vec<u8>)>, GCError> {
    let mut stmt = conn
        .prepare(
            "SELECT op_id, payload FROM oplog_db.oplog INDEXED BY idx_oplog_lww
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
             ORDER BY hlc ASC, device_id ASC, op_id ASC",
        )
        .map_err(|e| GCError::Other(format!("oplog ops_for_row_asc prepare: {e}")))?;
    let rows = stmt
        .query_map(params![store, table, row_pk], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| GCError::Other(format!("oplog ops_for_row_asc query: {e}")))?;
    let mut ops = Vec::new();
    for row in rows {
        let (op_id, payload) =
            row.map_err(|e| GCError::Other(format!("oplog ops_for_row_asc row: {e}")))?;
        if let Ok(arr) = <[u8; 32]>::try_from(op_id.as_slice()) {
            ops.push((OpId::from_bytes(arr), payload));
        }
    }
    Ok(ops)
}

/// Fetch a logged op's verbatim envelope by id, decoded. Used to re-drive a
/// buffered pending edge (P3-D6) whose op is already durable in the log.
pub fn load_op(conn: &rusqlite::Connection, id: &OpId) -> Result<Option<SignedOp>, GCError> {
    let envelope: Option<Vec<u8>> = conn
        .query_row(
            "SELECT envelope FROM oplog_db.oplog WHERE op_id = ?1",
            params![id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| GCError::Other(format!("oplog load_op: {e}")))?;
    match envelope {
        Some(bytes) => SignedOp::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| GCError::Other(format!("oplog load_op decode: {e}"))),
        None => Ok(None),
    }
}

/// Whether an op with this id is already logged.
pub fn contains(conn: &rusqlite::Connection, id: &OpId) -> Result<bool, GCError> {
    conn.query_row(
        "SELECT 1 FROM oplog_db.oplog WHERE op_id = ?1",
        params![id.as_bytes().as_slice()],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
    .map_err(|e| GCError::Other(format!("oplog contains: {e}")))
}

/// Highest order key across the *whole* log — the combined `/head` value and the
/// mesh resume cursor. Both stores share one `oplog` and the mesh serves a single
/// totally-ordered feed (rides `idx_oplog_order`), so the head spans every store;
/// the pull driver dispatches each op back to its store by `store_id`. A per-store
/// head (the snapshot watermark) is [`head_in_store`].
///
/// Pre-release format decision (2026-07-02): the served feed switched from
/// proxydb-only to all-store in the same changeset that introduced the FIRST
/// production puller — no earlier puller ever consumed the proxydb-only feed, so
/// there is no mixed-version negotiation to do. Any future feed-shape change
/// after release DOES need versioning on `/ops`.
pub fn head(conn: &rusqlite::Connection) -> Result<Option<OrderKey>, GCError> {
    conn.query_row(
        "SELECT hlc, device_id, op_id FROM oplog_db.oplog
         ORDER BY hlc DESC, device_id DESC, op_id DESC
         LIMIT 1",
        [],
        order_key_from_row,
    )
    .optional()
    .map_err(|e| GCError::Other(format!("oplog head: {e}")))
}

/// Highest order key for one store's slice of the log (P3-D9). The snapshot
/// watermark and per-store `/head` read through here; both stores share the
/// table (P3-D1) so the watermark is exactly `head_in_store` filtered by store.
pub fn head_in_store(
    conn: &rusqlite::Connection,
    store: &str,
) -> Result<Option<OrderKey>, GCError> {
    conn.query_row(
        "SELECT hlc, device_id, op_id FROM oplog_db.oplog
         WHERE store_id = ?1
         ORDER BY hlc DESC, device_id DESC, op_id DESC
         LIMIT 1",
        params![store],
        order_key_from_row,
    )
    .optional()
    .map_err(|e| GCError::Other(format!("oplog head_in_store: {e}")))
}

/// A page of envelopes strictly after `cursor` across *all* stores, in total
/// order, capped at `limit` — the single mesh `/ops` feed. The
/// `(hlc, device_id, op_id)` row-value comparison rides `idx_oplog_order`; the
/// pull driver dispatches each op to its store by `store_id`. A per-store slice
/// (snapshot bootstrap) is [`since_in_store`].
pub fn since(
    conn: &rusqlite::Connection,
    cursor: OrderKey,
    limit: usize,
) -> Result<Vec<SignedOp>, GCError> {
    let mut stmt = conn
        .prepare(
            "SELECT envelope FROM oplog_db.oplog
             WHERE (hlc, device_id, op_id) > (?1, ?2, ?3)
             ORDER BY hlc, device_id, op_id
             LIMIT ?4",
        )
        .map_err(|e| GCError::Other(format!("oplog since prepare: {e}")))?;
    let rows = stmt
        .query_map(
            params![
                cursor.hlc.0 as i64,
                cursor.device.as_bytes().as_slice(),
                cursor.op_id.as_bytes().as_slice(),
                limit as i64,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|e| GCError::Other(format!("oplog since query: {e}")))?;

    let mut ops = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| GCError::Other(format!("oplog since row: {e}")))?;
        // A row that fails to decode is a corrupt envelope; skip it rather than
        // abort serving the whole page.
        if let Ok(op) = SignedOp::from_bytes(&bytes) {
            ops.push(op);
        }
    }
    Ok(ops)
}

/// A page of one store's envelopes strictly after `cursor` (P3-D1). Both stores
/// share the table, so serving a store's `/ops` feed is the proxy.db `since`
/// filtered by `store_id`.
pub fn since_in_store(
    conn: &rusqlite::Connection,
    store: &str,
    cursor: OrderKey,
    limit: usize,
) -> Result<Vec<SignedOp>, GCError> {
    let mut stmt = conn
        .prepare(
            "SELECT envelope FROM oplog_db.oplog
             WHERE store_id = ?1
               AND (hlc, device_id, op_id) > (?2, ?3, ?4)
             ORDER BY hlc, device_id, op_id
             LIMIT ?5",
        )
        .map_err(|e| GCError::Other(format!("oplog since prepare: {e}")))?;
    let rows = stmt
        .query_map(
            params![
                store,
                cursor.hlc.0 as i64,
                cursor.device.as_bytes().as_slice(),
                cursor.op_id.as_bytes().as_slice(),
                limit as i64,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|e| GCError::Other(format!("oplog since query: {e}")))?;

    let mut ops = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| GCError::Other(format!("oplog since row: {e}")))?;
        // A row that fails to decode is a corrupt envelope; skip it rather than
        // abort serving the whole page.
        if let Ok(op) = SignedOp::from_bytes(&bytes) {
            ops.push(op);
        }
    }
    Ok(ops)
}

/// Observed op-log size as `(count, bytes)`: the number of logged ops and the
/// total bytes of their stored envelopes plus payloads. Cheap health/diagnostics
/// signal for the phase-2 unbounded-growth window (see the module retention note)
/// — one aggregate scan, no per-row work.
/// Op count high-water mark. The oplog is append-only, so `MAX(_rowid_)` is
/// an O(1) b-tree seek equal to the row count — never scan this table on a
/// health path: at tens of millions of ops a `COUNT(*) + SUM(LENGTH(...))`
/// scan held `/cli/system/health` for 25s+ under writer contention.
pub fn stats(conn: &rusqlite::Connection) -> Result<i64, GCError> {
    conn.query_row(
        "SELECT COALESCE(MAX(_rowid_), 0) FROM oplog_db.oplog",
        [],
        |row| row.get(0),
    )
    .map_err(|e| GCError::Other(format!("oplog stats: {e}")))
}

/// Load a peer's persisted resume cursor, or [`OrderKey::MIN`] if none.
pub fn load_cursor(conn: &rusqlite::Connection, peer: &DeviceId) -> Result<OrderKey, GCError> {
    let stored: Option<Vec<u8>> = conn
        .query_row(
            "SELECT cursor FROM oplog_db.sync_cursors WHERE peer_device_id = ?1",
            params![peer.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| GCError::Other(format!("load cursor: {e}")))?;
    match stored {
        Some(bytes) => match <[u8; 72]>::try_from(bytes.as_slice()) {
            Ok(arr) => Ok(OrderKey::from_wire(&arr)),
            Err(_) => Ok(OrderKey::MIN),
        },
        None => Ok(OrderKey::MIN),
    }
}

/// Persist a peer's resume cursor without ever moving it backwards. Called only
/// after the batch's ops are durable in the same WAL, so a recovered cursor
/// never points past ops the log lost. The wire encoding is big-endian and
/// lexicographically ordered, making the conflict predicate match `OrderKey`.
pub fn save_cursor(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    cursor: OrderKey,
) -> Result<(), GCError> {
    conn.execute(
        "INSERT INTO oplog_db.sync_cursors (peer_device_id, cursor) VALUES (?1, ?2)
         ON CONFLICT(peer_device_id) DO UPDATE SET cursor = excluded.cursor
         WHERE sync_cursors.cursor < excluded.cursor",
        params![peer.as_bytes().as_slice(), cursor.to_wire().as_slice()],
    )
    .map_err(|e| GCError::Other(format!("save cursor: {e}")))?;
    Ok(())
}
