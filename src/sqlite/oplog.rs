//! SQL-backed op-log storage (D1): the `oplog` and `sync_cursors` tables. All
//! functions take a `&Connection` so a local emit lands in the caller's business
//! transaction (D3) and a remote apply lands in its own (D5). Pruning lives in
//! [`super::retention`]; the tombstone invariant it must respect is documented
//! on the LWW guard ([`newest_applied`]).
//! The family lives in the attached `oplog.db` — placement inventory in
//! `crate::database::schema::oplog_db`, tear analysis on `ProxyDb::emit_ops`.

use crate::{DeviceId, Hlc, OpId, OrderKey, SignedOp};
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;
pub use super::oplog_heads::{
    HeadsBackfillChunk, backfill_heads_chunk_in_txn, demote_head, rebuild_head, upsert_head,
};
pub use super::pending_edges::{
    PendingEdgePage, buffer_pending_edge, discard_undispatched_move_callback,
    mark_move_callback_dispatched, move_callback_recorded, pending_edge_wake, pending_edges_for,
    pending_edges_remain, queue_pending_edge_wake, record_move_callback_fire, remove_pending_edge,
    remove_pending_edge_all, remove_pending_edge_wake, remove_pending_edges_for_edge_row,
    rotate_pending_edge_wake, undispatched_move_callback, undispatched_move_callbacks,
};
use crate::row_op::store_id;

/// Append a signed op's envelope plus its indexable projections. `INSERT OR
/// IGNORE` on the `op_id` primary key makes re-appending the same op a no-op, so
/// applying a pulled op twice is idempotent (D5). Returns whether the row was new.
///
/// The envelope is stored verbatim so the `/ops` route re-serves the exact bytes
/// the originating peer signed; the other columns are projections used for
/// ordering (`hlc, device_id, op_id`) and LWW (`store_id, table_name, row_pk`).
pub fn append(
    conn: &rusqlite::Connection,
    op: &SignedOp,
    table: &str,
    row_pk: &str,
    origin: i64,
) -> Result<bool, GCError> {
    let envelope = op
        .to_bytes()
        .map_err(|e| GCError::Other(format!("encode op envelope: {e}")))?;
    let changed = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO oplog_db.oplog
                (op_id, hlc, device_id, store_id, payload, envelope, table_name, row_pk, origin, applied)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
        )
        .and_then(|mut stmt| {
            stmt.execute(params![
                op.id.as_bytes().as_slice(),
                op.body.hlc.0 as i64,
                op.body.device.as_bytes().as_slice(),
                op.body.store.as_str(),
                op.body.payload,
                envelope,
                table,
                row_pk,
                origin,
            ])
        })
        .map_err(|e| GCError::Other(format!("oplog append: {e}")))?;
    if changed > 0 {
        conn.prepare_cached(
            "INSERT INTO oplog_db.oplog_arrivals (op_id, arrived_at)
             VALUES (?1, CAST(strftime('%s', 'now') AS INTEGER))",
        )
        .and_then(|mut s| s.execute(params![op.id.as_bytes().as_slice()]))
        .map_err(|e| GCError::Other(format!("oplog arrival append: {e}")))?;
        upsert_head(conn, op, table, row_pk)?;
        // Self-coverage (pull v3, channel A): our own emissions are contiguous
        // by construction, so claiming them keeps peers from re-serving our
        // history back to us. A remote arrival must NOT advance coverage here —
        // arrival order is not per-origin prefix-safe, so only the channel-A
        // apply path, which walks one origin ascending, may claim a remote one.
        if origin == crate::row_op::ORIGIN_LOCAL {
            super::coverage::note_own_op(conn, op)?;
        }
    }
    Ok(changed > 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStreamState {
    pub stream_epoch: [u8; 32],
    pub head_seq: u64,
    pub compacted_through_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayCursorState {
    pub stream_epoch: [u8; 32],
    pub relay_seq: u64,
}

/// This relay's durable transport stream identity and monotonic arrival head.
/// The signed operation order key remains the semantic LWW clock; `head_seq` is
/// only a lossless continuation position for this particular relay.
pub fn relay_stream_state(conn: &rusqlite::Connection) -> Result<RelayStreamState, GCError> {
    conn.query_row(
        "SELECT stream_epoch,
                COALESCE((SELECT MAX(relay_seq) FROM oplog_db.oplog_arrivals), 0),
                compacted_through_seq
         FROM oplog_db.mesh_relay_state WHERE singleton = 1",
        [],
        |row| {
            let epoch = row.get::<_, Vec<u8>>(0)?;
            let stream_epoch = <[u8; 32]>::try_from(epoch.as_slice()).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "relay stream epoch".into(),
                )
            })?;
            let head_seq = u64::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, i64::MIN))?;
            let compacted_through_seq = u64::try_from(row.get::<_, i64>(2)?)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, i64::MIN))?;
            Ok(RelayStreamState {
                stream_epoch,
                head_seq,
                compacted_through_seq,
            })
        },
    )
    .map_err(|e| GCError::Other(format!("relay stream state: {e}")))
}

/// Exact signed envelopes in relay-local first-arrival order. Sequence holes are
/// valid after compaction; callers advance to each returned sequence, never by
/// assuming contiguity.
pub fn relay_since(
    conn: &rusqlite::Connection,
    after: u64,
    limit: usize,
) -> Result<Vec<(u64, SignedOp)>, GCError> {
    Ok(relay_since_with_envelopes(conn, after, limit)?
        .into_iter()
        .map(|(seq, op, _)| (seq, op))
        .collect())
}

/// The same feed as [`relay_since`], keeping each verbatim envelope beside its
/// decoded operation. Pull v3 serves this: it filters on the decoded order key
/// but must forward the bytes the origin device signed, not a re-encoding.
pub fn relay_since_with_envelopes(
    conn: &rusqlite::Connection,
    after: u64,
    limit: usize,
) -> Result<Vec<(u64, SignedOp, Vec<u8>)>, GCError> {
    let after = i64::try_from(after)
        .map_err(|_| GCError::InvalidArgument("relay cursor exceeds SQLite range".into()))?;
    let limit = i64::try_from(limit)
        .map_err(|_| GCError::InvalidArgument("relay page limit exceeds SQLite range".into()))?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT arrivals.relay_seq, oplog.envelope
             FROM oplog_db.oplog_arrivals AS arrivals
             JOIN oplog_db.oplog ON oplog.op_id = arrivals.op_id
             WHERE arrivals.relay_seq > ?1
             ORDER BY arrivals.relay_seq
             LIMIT ?2",
        )
        .map_err(|e| GCError::Other(format!("relay since prepare: {e}")))?;
    let rows = stmt
        .query_map(params![after, limit], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| GCError::Other(format!("relay since query: {e}")))?;
    let mut entries = Vec::new();
    for row in rows {
        let (seq, envelope) = row.map_err(|e| GCError::Other(format!("relay since row: {e}")))?;
        let seq =
            u64::try_from(seq).map_err(|_| GCError::Other("relay sequence is negative".into()))?;
        let op = SignedOp::from_bytes(&envelope)
            .map_err(|e| GCError::Other(format!("relay envelope decode: {e}")))?;
        entries.push((seq, op, envelope));
    }
    Ok(entries)
}

/// One origin's envelopes strictly above `after` (`None` = from the beginning),
/// ascending, optionally filtered to one `store_id`. Unscoped pulls ride
/// `idx_oplog_origin`, built by the coverage priming sweep. Store sweeps ride
/// `idx_oplog_store` so a small store never scans the unrelated history of an
/// origin. Callers must gate on [`super::coverage::is_primed`].
pub fn origin_since(
    conn: &rusqlite::Connection,
    origin: &DeviceId,
    after: Option<OrderKey>,
    store: Option<&str>,
    limit: usize,
) -> Result<Vec<(OrderKey, Vec<u8>)>, GCError> {
    // An HLC is a wall-clock milliseconds value, so -1 sorts below every real
    // key and makes the open lower bound the same row-value comparison.
    let (after_hlc, after_op_id) = match after {
        Some(key) => (key.hlc.0 as i64, key.op_id.as_bytes().to_vec()),
        None => (-1, Vec::new()),
    };
    let sql = if store.is_some() {
        "SELECT hlc, op_id, envelope FROM oplog_db.oplog INDEXED BY idx_oplog_store
         WHERE store_id = ?4 AND device_id = ?1
           AND (hlc, device_id, op_id) > (?2, ?1, ?3)
         ORDER BY hlc, device_id, op_id
         LIMIT ?5"
    } else {
        "SELECT hlc, op_id, envelope FROM oplog_db.oplog INDEXED BY idx_oplog_origin
         WHERE device_id = ?1 AND (hlc, op_id) > (?2, ?3)
         ORDER BY hlc, op_id
         LIMIT ?5"
    };
    let mut stmt = conn
        .prepare_cached(sql)
        .map_err(|e| GCError::Other(format!("origin since prepare: {e}")))?;
    let rows = stmt
        .query_map(
            params![
                origin.as_bytes().as_slice(),
                after_hlc,
                after_op_id,
                store,
                limit as i64
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|e| GCError::Other(format!("origin since query: {e}")))?;
    let mut entries = Vec::new();
    for row in rows {
        let (hlc, op_id, envelope) =
            row.map_err(|e| GCError::Other(format!("origin since row: {e}")))?;
        let Ok(op_id) = <[u8; 32]>::try_from(op_id.as_slice()) else {
            continue;
        };
        entries.push((
            OrderKey {
                hlc: Hlc(hlc as u64),
                device: *origin,
                op_id: OpId::from_bytes(op_id),
            },
            envelope,
        ));
    }
    Ok(entries)
}

pub fn load_relay_cursor(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
) -> Result<Option<RelayCursorState>, GCError> {
    conn.prepare_cached(
        "SELECT stream_epoch, relay_seq FROM oplog_db.mesh_relay_cursors
         WHERE peer_device_id = ?1 AND protocol_version = 2",
    )
    .and_then(|mut stmt| {
        stmt.query_row(params![peer.as_bytes().as_slice()], |row| {
            let epoch = row.get::<_, Vec<u8>>(0)?;
            let stream_epoch = <[u8; 32]>::try_from(epoch.as_slice()).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "relay cursor epoch".into(),
                )
            })?;
            let relay_seq = u64::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, i64::MIN))?;
            Ok(RelayCursorState {
                stream_epoch,
                relay_seq,
            })
        })
        .optional()
    })
    .map_err(|e| GCError::Other(format!("load relay cursor: {e}")))
}

pub fn reset_relay_cursor(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    stream_epoch: [u8; 32],
    relay_seq: u64,
) -> Result<(), GCError> {
    conn.execute(
        "INSERT INTO oplog_db.mesh_relay_cursors (
            peer_device_id, protocol_version, stream_epoch, relay_seq, updated_at
         ) VALUES (?1, 2, ?2, ?3, datetime('now'))
         ON CONFLICT(peer_device_id) DO UPDATE
         SET protocol_version = 2,
             stream_epoch = excluded.stream_epoch,
             relay_seq = excluded.relay_seq,
             updated_at = excluded.updated_at",
        params![
            peer.as_bytes().as_slice(),
            stream_epoch.as_slice(),
            relay_seq as i64
        ],
    )
    .map_err(|e| GCError::Other(format!("reset relay cursor: {e}")))?;
    Ok(())
}

pub fn save_relay_cursor(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    cursor: RelayCursorState,
) -> Result<(), GCError> {
    let relay_seq = i64::try_from(cursor.relay_seq)
        .map_err(|_| GCError::InvalidArgument("relay cursor exceeds SQLite range".into()))?;
    conn.prepare_cached(
        "INSERT INTO oplog_db.mesh_relay_cursors (
            peer_device_id, protocol_version, stream_epoch, relay_seq, updated_at
         ) VALUES (?1, 2, ?2, ?3, datetime('now'))
         ON CONFLICT(peer_device_id) DO UPDATE
         SET protocol_version = 2,
             stream_epoch = excluded.stream_epoch,
             relay_seq = CASE
                 WHEN mesh_relay_cursors.stream_epoch = excluded.stream_epoch
                 THEN MAX(mesh_relay_cursors.relay_seq, excluded.relay_seq)
                 ELSE excluded.relay_seq
             END,
             updated_at = excluded.updated_at",
    )
    .and_then(|mut s| {
        s.execute(params![
            peer.as_bytes().as_slice(),
            cursor.stream_epoch.as_slice(),
            relay_seq
        ])
    })
    .map_err(|e| GCError::Other(format!("save relay cursor: {e}")))?;
    Ok(())
}

pub fn rotate_relay_stream_epoch(conn: &rusqlite::Connection) -> Result<(), GCError> {
    conn.execute(
        "UPDATE oplog_db.mesh_relay_state
         SET stream_epoch = randomblob(32), compacted_through_seq = 0
         WHERE singleton = 1",
        [],
    )
    .map_err(|e| GCError::Other(format!("rotate relay stream epoch: {e}")))?;
    Ok(())
}

/// The highest applied order key written to `(table, row_pk)`, excluding
/// `exclude` — the current LWW winner for that row (D6), ignoring the op being
/// applied so the guard is order-independent whether or not that op is already
/// logged. A single seek on `idx_oplog_lww`.
pub fn newest_applied(
    conn: &rusqlite::Connection,
    table: &str,
    row_pk: &str,
    exclude: &OpId,
) -> Result<Option<OrderKey>, GCError> {
    newest_applied_in_store(conn, store_id().as_str(), table, row_pk, exclude)
}

/// The LWW winner (D6) for `(store, table, row_pk)`, ignoring `exclude`. The
/// store-parameterized form the Trellis adapter (P3-D1) shares with proxy.db:
/// both stores live in one `oplog`, keyed apart by `store_id`.
pub fn newest_applied_in_store(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
    exclude: &OpId,
) -> Result<Option<OrderKey>, GCError> {
    // The materialized head answers directly whenever it is not the excluded op:
    // excluding a non-winner cannot change the winner. Only when the head IS the
    // excluded op (or the head row is absent) does the indexed per-row scan run —
    // the pre-heads plan, one seek on idx_oplog_lww.
    let head = conn
        .prepare_cached(
            "SELECT hlc, device_id, op_id FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![store, table, row_pk], order_key_from_row)
                .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog newest_applied_in_store head: {e}")))?;
    if let Some(key) = head {
        if key.op_id != *exclude {
            return Ok(Some(key));
        }
    }
    conn.prepare_cached(
        "SELECT hlc, device_id, op_id FROM oplog_db.oplog INDEXED BY idx_oplog_lww
         WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
           AND op_id != ?4
         ORDER BY hlc DESC, device_id DESC, op_id DESC
         LIMIT 1",
    )
    .and_then(|mut stmt| {
        stmt.query_row(
            params![store, table, row_pk, exclude.as_bytes().as_slice()],
            order_key_from_row,
        )
        .optional()
    })
    .map_err(|e| GCError::Other(format!("oplog newest_applied_in_store: {e}")))
}

/// The newest applied op's order key *and* its decoded payload for
/// `(store, table, row_pk)`, ignoring `exclude`. The Trellis repair rules
/// (P3-D6/D7) need the payload to tell an `Upsert` endpoint from a `Delete`
/// tombstone, which the bare [`newest_applied_in_store`] order key cannot express.
pub fn newest_op_in_store(
    conn: &rusqlite::Connection,
    store: &str,
    table: &str,
    row_pk: &str,
    exclude: &OpId,
) -> Result<Option<(OrderKey, Vec<u8>)>, GCError> {
    // Same head-first read as `newest_applied_in_store`, carrying the payload.
    let head = conn
        .prepare_cached(
            "SELECT hlc, device_id, op_id, payload FROM oplog_db.oplog_heads
             WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3",
        )
        .and_then(|mut stmt| {
            stmt.query_row(params![store, table, row_pk], |row| {
                Ok((order_key_from_row(row)?, row.get::<_, Vec<u8>>(3)?))
            })
            .optional()
        })
        .map_err(|e| GCError::Other(format!("oplog newest_op_in_store head: {e}")))?;
    if let Some((key, payload)) = head {
        if key.op_id != *exclude {
            return Ok(Some((key, payload)));
        }
    }
    conn.prepare_cached(
        "SELECT hlc, device_id, op_id, payload FROM oplog_db.oplog INDEXED BY idx_oplog_lww
         WHERE store_id = ?1 AND table_name = ?2 AND row_pk = ?3 AND applied = 1
           AND op_id != ?4
         ORDER BY hlc DESC, device_id DESC, op_id DESC
         LIMIT 1",
    )
    .and_then(|mut stmt| {
        stmt.query_row(
            params![store, table, row_pk, exclude.as_bytes().as_slice()],
            |row| Ok((order_key_from_row(row)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
    })
    .map_err(|e| GCError::Other(format!("oplog newest_op_in_store: {e}")))
}

/// Batched [`newest_op_in_store`] (exclude-nothing form): the newest applied
/// op's payload for every `row_pk` in the set, keyed by `row_pk`. Rows with no
/// applied op are absent from the map. One window-function query per chunk of
/// ids instead of one seek per row, so a full-graph reconcile detection pass
/// costs a handful of statements rather than one per element.
pub use super::oplog_queries::*;

pub(crate) fn order_key_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OrderKey> {
    let hlc: i64 = row.get(0)?;
    let device: Vec<u8> = row.get(1)?;
    let op_id: Vec<u8> = row.get(2)?;
    let device = <[u8; 32]>::try_from(device.as_slice()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Blob,
            "device id".into(),
        )
    })?;
    let op_id = <[u8; 32]>::try_from(op_id.as_slice()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, "op id".into())
    })?;
    Ok(OrderKey {
        hlc: Hlc(hlc as u64),
        device: DeviceId::from_bytes(device),
        op_id: OpId::from_bytes(op_id),
    })
}
