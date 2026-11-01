//! Maintenance of `oplog_heads` — the materialized LWW winner per
//! `(store, table, row_pk)`. Every mutation runs pure SQL on the caller's
//! connection so it composes with whatever transaction wraps the oplog write.

use crate::{OpId, SignedOp};
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;

/// Maintain the row's materialized LWW head in `oplog_heads` for an applied op:
/// insert the head, or advance it iff the op's `(hlc, device_id, op_id)` order
/// key beats the stored one — the same total order every LWW reader uses.
///
/// `origin_device` tracks the row's *earliest* applied op's device (the value
/// [`origin_device`] historically derived by ASC scan): it is overwritten only
/// when the incoming op orders below every other applied op for the row, so an
/// out-of-order older arrival (a creation filling in after its resolution)
/// corrects it, while after compaction drops the true-earliest op the stored
/// fact persists — no surviving op undercuts the minimum. Pure SQL on the
/// caller's connection: it runs inside whatever transaction wraps the oplog
/// write, never opening its own. Called from [`append`] (every new op is
/// inserted `applied = 1`) and from the deferred external-row canonicalization
/// path when it re-marks a demoted op applied under its canonical projection.
pub fn upsert_head(
    conn: &rusqlite::Connection,
    op: &SignedOp,
    table: &str,
    row_pk: &str,
) -> Result<(), GCError> {
    conn.prepare_cached(
        "INSERT INTO oplog_db.oplog_heads
            (store_id, table_name, row_pk, hlc, device_id, op_id, payload, origin_device)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?5)
         ON CONFLICT(store_id, table_name, row_pk) DO UPDATE SET
             hlc = excluded.hlc,
             device_id = excluded.device_id,
             op_id = excluded.op_id,
             payload = excluded.payload
         WHERE (excluded.hlc, excluded.device_id, excluded.op_id)
             > (oplog_heads.hlc, oplog_heads.device_id, oplog_heads.op_id)",
    )
    .and_then(|mut stmt| {
        stmt.execute(params![
            op.body.store.as_str(),
            table,
            row_pk,
            op.body.hlc.0 as i64,
            op.body.device.as_bytes().as_slice(),
            op.id.as_bytes().as_slice(),
            op.body.payload,
        ])
    })
    .map_err(|e| GCError::Other(format!("oplog upsert head: {e}")))?;
    conn.prepare_cached(
        "UPDATE oplog_db.oplog_heads SET origin_device = ?5
         WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
           AND NOT EXISTS (
             SELECT 1 FROM oplog_db.oplog INDEXED BY idx_oplog_lww
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
               AND (hlc, device_id, op_id) < (?4, ?5, ?6)
           )",
    )
    .and_then(|mut stmt| {
        stmt.execute(params![
            op.body.store.as_str(),
            table,
            row_pk,
            op.body.hlc.0 as i64,
            op.body.device.as_bytes().as_slice(),
            op.id.as_bytes().as_slice(),
        ])
    })
    .map_err(|e| GCError::Other(format!("oplog head origin: {e}")))?;
    Ok(())
}

/// Retract an op from `oplog_heads` after it was marked `applied = 0` (an
/// external-row op deferred for canonicalization): if the op is some row's head,
/// re-derive that row's head from the remaining applied ops, or drop the head row
/// when none remain. Runs in the caller's transaction, after the `applied = 0`
/// update, so the re-derivation never re-elects the demoted op. The stored
/// `origin_device` is preserved when a replacement head exists.
pub fn demote_head(conn: &rusqlite::Connection, op_id: &OpId) -> Result<(), GCError> {
    // `idx_oplog_heads_op` predates the split oplog database and is absent on
    // some upgraded installations. Resolve the row through oplog's op-id
    // primary key, then verify the head through its row primary key. Both
    // probes stay logarithmic without relying on that optional legacy index.
    let coordinates: Option<(String, String, String)> = conn
        .prepare_cached(
            "SELECT store_id, table_name, row_pk
             FROM oplog_db.oplog
             WHERE op_id = ?1",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![op_id.as_bytes().as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog demote coordinates lookup: {e}")))?;
    let Some((store, table, row_pk)) = coordinates else {
        return Ok(());
    };
    let is_head: bool = conn
        .prepare_cached(
            "SELECT EXISTS (
                 SELECT 1 FROM oplog_db.oplog_heads
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND op_id = ?4
             )",
        )
        .and_then(|mut stmt| {
            stmt.query_row(
                params![store, table, row_pk, op_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
        })
        .map_err(|e| GCError::Other(format!("oplog demote head lookup: {e}")))?;
    if !is_head {
        return Ok(());
    }
    let updated = conn
        .prepare_cached(
            "UPDATE oplog_db.oplog_heads
             SET (hlc, device_id, op_id, payload) = (
                 SELECT hlc, device_id, op_id, payload
                 FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                 ORDER BY hlc DESC, device_id DESC, op_id DESC
                 LIMIT 1
             )
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
               AND EXISTS (
                 SELECT 1 FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
               )",
        )
        .and_then(|mut stmt| stmt.execute(params![store, table, row_pk]))
        .map_err(|e| GCError::Other(format!("oplog demote head rederive: {e}")))?;
    if updated == 0 {
        conn.prepare_cached(
            "DELETE FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| stmt.execute(params![store, table, row_pk]))
        .map_err(|e| GCError::Other(format!("oplog demote head delete: {e}")))?;
    }
    Ok(())
}

/// Re-derive one row's `oplog_heads` entry from scratch — head values and
/// `origin_device` both — or drop it when the row has no applied ops. Used when
/// ops *move between row partitions*: an alias merge
/// ([`crate::database::external_row_ids::remember_alias`]) rewrites `row_pk` on
/// existing oplog rows, which the incremental [`upsert_head`]/[`demote_head`]
/// maintenance never sees. The origin is re-derived by ASC scan of the merged
/// partition; the compactor pins every row's earliest applied op, so the scan
/// still names the true minimum after pruning. Runs on the caller's connection,
/// inside whatever transaction rewrote the partition.
pub fn rebuild_head(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
) -> Result<(), GCError> {
    let rebuilt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO oplog_db.oplog_heads
                (store_id, table_name, row_pk, hlc, device_id, op_id, payload, origin_device)
             SELECT ?1, ?2, ?3, newest.hlc, newest.device_id, newest.op_id, newest.payload,
                    (SELECT device_id FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                     WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                     ORDER BY hlc ASC, device_id ASC, op_id ASC
                     LIMIT 1)
             FROM (
                 SELECT hlc, device_id, op_id, payload FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                 ORDER BY hlc DESC, device_id DESC, op_id DESC
                 LIMIT 1
             ) AS newest",
        )
        .and_then(|mut stmt| stmt.execute(params![store, table, row_pk]))
        .map_err(|e| GCError::Other(format!("oplog rebuild head: {e}")))?;
    if rebuilt == 0 {
        conn.prepare_cached(
            "DELETE FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| stmt.execute(params![store, table, row_pk]))
        .map_err(|e| GCError::Other(format!("oplog rebuild head clear: {e}")))?;
    }
    Ok(())
}
