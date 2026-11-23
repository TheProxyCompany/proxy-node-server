//! Maintenance of `oplog_heads`: the materialized LWW winner per
//! `(store, table, row_pk)`. Every mutation runs pure SQL on the caller's
//! connection so it composes with whatever transaction wraps the oplog write.

use crate::{OpId, SignedOp};
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;

/// Maintain the row's materialized LWW head in `oplog_heads` for an applied op:
/// insert the head, or advance it iff the op's `(hlc, device_id, op_id)` order
/// key beats the stored one, using the same total order every LWW reader uses.
///
/// `origin_device` tracks the row's earliest applied op's device. Once horizon
/// compaction prunes historical ops from `oplog_db.oplog`, `origin_device` must
/// never be overwritten by a newer head update; it only updates when `origin_device`
/// is missing or when an out-of-order incoming op orders strictly below both the
/// stored head and any surviving applied ops for the row.
pub fn upsert_head(
    conn: &rusqlite::Connection,
    op: &SignedOp,
    table: &str,
    row_pk: &str,
) -> Result<(), GCError> {
    conn.prepare_cached(
        "UPDATE oplog_db.oplog_heads SET origin_device = ?5
         WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
           AND (
             origin_device IS NULL
             OR (
               (?4, ?5, ?6) < (oplog_heads.hlc, oplog_heads.device_id, oplog_heads.op_id)
               AND NOT EXISTS (
                 SELECT 1 FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                   AND (hlc, device_id, op_id) < (?4, ?5, ?6)
               )
             )
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
    let store_empty_head_payload = op.body.store.as_str() == "proxydb"
        && super::retention_pins::HEAD_PAYLOAD_TRIM_TABLES.contains(&table)
        && crate::row_op::ProxyDbOp::decode_bytes(&op.body.payload).is_ok_and(|decoded| {
            matches!(decoded.mutation, crate::row_op::Mutation::Upsert { .. })
        });
    let head_payload: &[u8] = if store_empty_head_payload {
        &[]
    } else {
        op.body.payload.as_slice()
    };
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
            head_payload,
        ])
    })
    .map_err(|e| GCError::Other(format!("oplog upsert head: {e}")))?;
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
    let replacement: Option<(i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .prepare_cached(
            "SELECT hlc, device_id, op_id, payload, envelope
             FROM oplog_db.oplog INDEXED BY idx_oplog_lww
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
             ORDER BY hlc DESC, device_id DESC, op_id DESC
             LIMIT 1",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![store, table, row_pk], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog demote head select: {e}")))?;
    if let Some((hlc, device_id, next_op_id, payload, envelope)) = replacement {
        let resolved_payload = if !payload.is_empty() {
            payload
        } else {
            SignedOp::from_bytes(&envelope)
                .map(|op| op.body.payload)
                .unwrap_or_default()
        };
        conn.prepare_cached(
            "UPDATE oplog_db.oplog_heads
             SET hlc = ?4, device_id = ?5, op_id = ?6, payload = ?7
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| {
            stmt.execute(params![
                store,
                table,
                row_pk,
                hlc,
                device_id,
                next_op_id,
                resolved_payload
            ])
        })
        .map_err(|e| GCError::Other(format!("oplog demote head rederive: {e}")))?;
    } else {
        conn.prepare_cached(
            "DELETE FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| stmt.execute(params![store, table, row_pk]))
        .map_err(|e| GCError::Other(format!("oplog demote head delete: {e}")))?;
    }
    Ok(())
}

/// Re-derive one row's `oplog_heads` entry when ops move between row partitions
/// (for example external-row alias folding). If the existing head's op was
/// already horizon-pruned from `oplog_db.oplog`, that compacted head is preserved
/// unless a surviving applied op in `oplog` outranks it.
pub fn rebuild_head(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
) -> Result<(), GCError> {
    let existing_pruned_head: Option<(i64, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>)> = conn
        .prepare_cached(
            "SELECT h.hlc, h.device_id, h.op_id, h.payload, h.origin_device
             FROM oplog_db.oplog_heads AS h
             WHERE h.store_id = ?1 AND h.table_name = ?2 AND h.row_pk = ?3
               AND NOT EXISTS (
                   SELECT 1 FROM oplog_db.oplog AS o WHERE o.op_id = h.op_id
               )",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![store, table, row_pk], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog rebuild existing head: {e}")))?;

    let newest: Option<(i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .prepare_cached(
            "SELECT hlc, device_id, op_id, payload, envelope
             FROM oplog_db.oplog INDEXED BY idx_oplog_lww
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
             ORDER BY hlc DESC, device_id DESC, op_id DESC
             LIMIT 1",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![store, table, row_pk], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog rebuild head select: {e}")))?;

    if let Some((hlc, device_id, op_id, payload, envelope)) = newest {
        if let Some((h_hlc, ref h_dev, ref h_op, _, _)) = existing_pruned_head {
            if (h_hlc, h_dev.as_slice(), h_op.as_slice())
                >= (hlc, device_id.as_slice(), op_id.as_slice())
            {
                return Ok(());
            }
        }
        let resolved_payload = if !payload.is_empty() {
            payload
        } else {
            SignedOp::from_bytes(&envelope)
                .map(|op| op.body.payload)
                .unwrap_or_default()
        };
        let preserved_origin = existing_pruned_head.and_then(|(_, _, _, _, origin)| origin);
        conn.prepare_cached(
            "INSERT OR REPLACE INTO oplog_db.oplog_heads
                (store_id, table_name, row_pk, hlc, device_id, op_id, payload, origin_device)
             VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                COALESCE(
                    ?8,
                    (SELECT device_id FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                     WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                     ORDER BY hlc ASC, device_id ASC, op_id ASC
                     LIMIT 1)
                )
             )",
        )
        .and_then(|mut stmt| {
            stmt.execute(params![
                store,
                table,
                row_pk,
                hlc,
                device_id,
                op_id,
                resolved_payload,
                preserved_origin,
            ])
        })
        .map_err(|e| GCError::Other(format!("oplog rebuild head: {e}")))?;
    } else if existing_pruned_head.is_none() {
        conn.prepare_cached(
            "DELETE FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| stmt.execute(params![store, table, row_pk]))
        .map_err(|e| GCError::Other(format!("oplog rebuild head clear: {e}")))?;
    }
    Ok(())
}
