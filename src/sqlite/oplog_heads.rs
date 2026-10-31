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

/// One bounded pass of the background `oplog_heads` backfill.
#[derive(Debug, Clone)]
pub struct HeadsBackfillChunk {
    /// Distinct `(store, table, row_pk)` groups the chunk scanned.
    pub scanned: usize,
    /// Groups whose head row was inserted, advanced, or origin-corrected.
    pub repaired: usize,
    /// The last group scanned — the next chunk's exclusive lower bound.
    /// `None` when the chunk reached the end of the log.
    pub cursor: Option<(String, String, String)>,
}

/// Backfill `oplog_heads` for up to `limit` row groups after `cursor`, in one
/// immediate transaction. The v83 migration creates the table empty (the
/// original in-migration backfill blocked boot for over an hour on a 25M-row
/// log); this chunk is the background replacement, spawned from `lib.rs` right
/// after open and driven to completion. Readers stay correct throughout: every
/// head consumer falls back to the `idx_oplog_lww` per-row seek while a row's
/// head is absent.
///
/// Per group it derives the LWW winner (DESC seek) and the earliest applied
/// op's device (ASC seek), then repairs the head under exactly
/// [`upsert_head`]'s conflict rule — insert when absent, advance only when the
/// derived key beats the stored one — so a head written by the live append
/// path always wins on a newer order key, while a head minted during the
/// backfill window from a single out-of-order arrival (or carrying that
/// arrival's device as origin) is corrected to the log-derived truth. The
/// origin overwrite is sound because compaction pins every row's earliest
/// applied op, so the ASC scan names the same monotone minimum `upsert_head`
/// maintains. Idempotent: a second pass over covered groups changes nothing.
pub fn backfill_heads_chunk_in_txn(
    conn: &rusqlite::Connection,
    cursor: Option<&(String, String, String)>,
    limit: usize,
) -> Result<HeadsBackfillChunk, GCError> {
    (|| {
        let groups: Vec<(String, String, String)> = {
            let (sql, bind_cursor) = match cursor {
                Some(_) => (
                    "SELECT store_id, table_name, row_pk
                     FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                     WHERE (store_id, table_name, row_pk) > (?2, ?3, ?4)
                     GROUP BY store_id, table_name, row_pk
                     ORDER BY store_id, table_name, row_pk
                     LIMIT ?1",
                    true,
                ),
                None => (
                    "SELECT store_id, table_name, row_pk
                     FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                     GROUP BY store_id, table_name, row_pk
                     ORDER BY store_id, table_name, row_pk
                     LIMIT ?1",
                    false,
                ),
            };
            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| GCError::Other(format!("heads backfill scan prepare: {e}")))?;
            let map = |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            };
            let rows = if bind_cursor {
                let (store, table, row_pk) = cursor.expect("cursor bound");
                stmt.query_map(params![limit as i64, store, table, row_pk], map)
            } else {
                stmt.query_map(params![limit as i64], map)
            }
            .map_err(|e| GCError::Other(format!("heads backfill scan: {e}")))?;
            rows.collect::<Result<_, _>>()
                .map_err(|e| GCError::Other(format!("heads backfill scan row: {e}")))?
        };

        let mut newest_stmt = conn
            .prepare(
                "SELECT hlc, device_id, op_id, payload FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                 ORDER BY hlc DESC, device_id DESC, op_id DESC
                 LIMIT 1",
            )
            .map_err(|e| GCError::Other(format!("heads backfill newest prepare: {e}")))?;
        let mut earliest_stmt = conn
            .prepare(
                "SELECT device_id FROM oplog_db.oplog INDEXED BY idx_oplog_lww
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
                 ORDER BY hlc ASC, device_id ASC, op_id ASC
                 LIMIT 1",
            )
            .map_err(|e| GCError::Other(format!("heads backfill earliest prepare: {e}")))?;
        let mut upsert_stmt = conn
            .prepare(
                "INSERT INTO oplog_db.oplog_heads
                    (store_id, table_name, row_pk, hlc, device_id, op_id, payload, origin_device)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(store_id, table_name, row_pk) DO UPDATE SET
                     hlc = excluded.hlc,
                     device_id = excluded.device_id,
                     op_id = excluded.op_id,
                     payload = excluded.payload
                 WHERE (excluded.hlc, excluded.device_id, excluded.op_id)
                     > (oplog_heads.hlc, oplog_heads.device_id, oplog_heads.op_id)",
            )
            .map_err(|e| GCError::Other(format!("heads backfill upsert prepare: {e}")))?;
        let mut origin_stmt = conn
            .prepare(
                "UPDATE oplog_db.oplog_heads SET origin_device = ?4
                 WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3
                   AND origin_device IS NOT ?4",
            )
            .map_err(|e| GCError::Other(format!("heads backfill origin prepare: {e}")))?;

        let mut repaired = 0usize;
        for (store, table, row_pk) in &groups {
            let newest: Option<(i64, Vec<u8>, Vec<u8>, Vec<u8>)> = newest_stmt
                .query_row(params![store, table, row_pk], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .optional()
                .map_err(|e| GCError::Other(format!("heads backfill newest: {e}")))?;
            // A group whose ops are all unapplied has no head by definition.
            let Some((hlc, device_id, op_id, payload)) = newest else {
                continue;
            };
            let origin: Vec<u8> = earliest_stmt
                .query_row(params![store, table, row_pk], |row| row.get(0))
                .map_err(|e| GCError::Other(format!("heads backfill earliest: {e}")))?;
            let upserted = upsert_stmt
                .execute(params![
                    store, table, row_pk, hlc, device_id, op_id, payload, origin
                ])
                .map_err(|e| GCError::Other(format!("heads backfill upsert: {e}")))?;
            let origined = origin_stmt
                .execute(params![store, table, row_pk, origin])
                .map_err(|e| GCError::Other(format!("heads backfill origin: {e}")))?;
            if upserted + origined > 0 {
                repaired += 1;
            }
        }

        let scanned = groups.len();
        let cursor = if scanned < limit {
            None
        } else {
            groups.last().cloned()
        };
        Ok(HeadsBackfillChunk {
            scanned,
            repaired,
            cursor,
        })
    })()
}

/// `schema_meta` key recording the repair version whose heads backfill has
/// completed on this device.
///
/// `schema_meta` and not `app_config`: the coverage sweep's flag lives in
/// `app_config`, which is a replicated table, so it has to re-verify its index
/// exists because a merged snapshot can import another device's flag wholesale.
/// `schema_meta` is outside mesh emission scope entirely — a flag here means
/// *this* device did the work.
const HEADS_BACKFILL_VERSION_KEY: &str = "mesh.oplog_heads_backfill_version";

/// Bump to force every device to re-run the full backfill once, e.g. when a
/// migration changes what a correct head looks like.
pub const HEADS_BACKFILL_REPAIR_VERSION: u32 = 1;

/// Whether the full backfill has already completed on this device at the
/// current repair version.
///
/// The sweep is a repair pass, not an incremental build: once it covers the
/// log, [`upsert_head`] on the live append path keeps every new op's head
/// current, so re-scanning every group on the next boot can only ever confirm
/// what the last scan proved. On a 1.3M-group log that confirmation cost 17
/// seconds of a 58-second boot and repaired nothing across 28 consecutive
/// launches.
///
/// The emptiness check is not belt-and-braces, for the same reason coverage
/// re-checks its index: the flag records that a scan finished, and a heads
/// table emptied since (a restore, a manual repair, a migration that rebuilds
/// it) would leave the flag true over an uncovered log. Both probes are
/// index-only `EXISTS` seeks, not counts.
pub fn heads_backfill_complete(conn: &rusqlite::Connection) -> Result<bool, GCError> {
    let recorded: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1 LIMIT 1",
            params![HEADS_BACKFILL_VERSION_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| GCError::Other(format!("heads backfill version read: {e}")))?;
    let covered = recorded
        .and_then(|raw| raw.parse::<u32>().ok())
        .is_some_and(|version| version >= HEADS_BACKFILL_REPAIR_VERSION);
    if !covered {
        return Ok(false);
    }
    let heads_empty: bool = conn
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM oplog_db.oplog_heads)",
            [],
            |row| row.get(0),
        )
        .map_err(|e| GCError::Other(format!("heads backfill emptiness probe: {e}")))?;
    if !heads_empty {
        return Ok(true);
    }
    // Empty heads over an empty log is covered, trivially and correctly.
    let oplog_empty: bool = conn
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM oplog_db.oplog)",
            [],
            |row| row.get(0),
        )
        .map_err(|e| GCError::Other(format!("heads backfill oplog probe: {e}")))?;
    Ok(oplog_empty)
}

/// Record that a full scan completed with nothing left to repair.
pub fn mark_heads_backfill_complete(conn: &rusqlite::Connection) -> Result<(), GCError> {
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![
            HEADS_BACKFILL_VERSION_KEY,
            HEADS_BACKFILL_REPAIR_VERSION.to_string()
        ],
    )
    .map_err(|e| GCError::Other(format!("heads backfill version write: {e}")))?;
    Ok(())
}
