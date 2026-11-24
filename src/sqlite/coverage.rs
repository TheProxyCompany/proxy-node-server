//! Per-origin high-water marks (pull v3, channel A) and the peer
//! acknowledgments compaction's floor rests on.
//!
//! ## Coverage is device-local pull state
//!
//! `mesh_origin_coverage` records, per origin device, the highest order key
//! this device asks a serving peer NOT to re-send on the keyed channel. It is
//! never exported, never folded from another device's claim, and never an
//! assertion that this device possesses everything below it. A claim that
//! exceeds possession — from priming off a scope-filtered log, from a run this
//! device declined by scope, from a clock regression — costs nothing: the
//! positional channel still delivers every arrival at or below the claim (see
//! the completeness argument in [`super::pull_v3`]). Only the reverse would be
//! unsafe, and claims never advance past what was verified and applied.
//!
//! Local emission advances self-coverage through [`note_own_op`] so this
//! device never asks a peer to re-serve its own ops. Remote arrivals do NOT
//! advance coverage here: remote arrival order is not per-origin prefix-safe,
//! so only the channel-A apply path — which walks one origin ascending — may
//! advance a remote origin's claim.
//!
//! ## Peer acks
//!
//! `mesh_peer_acks` records the channel-B cursor each pulling peer last
//! presented, qualified by the epoch it presented against. That is a real
//! served-cursor feed, so [`min_peer_ack`] gives retention a floor built from
//! what peers have durably walked. A trusted peer with no row for the current
//! epoch counts zero, which collapses the term and leaves the 30-day horizon
//! binding — bit-identical to pre-v3 behavior on a mixed fleet. The one
//! exception is a pairing silent past the retention horizon: a dead device
//! must not pin the floor at zero forever, so it drops out of the term until
//! it pulls again.

use std::collections::BTreeMap;

use crate::{DeviceId, Hlc, OpId, OrderKey, SignedOp};
use rusqlite::{OptionalExtension, params};

use super::SqliteError as GCError;

/// This device's claims, keyed by origin device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageVector(pub BTreeMap<DeviceId, OrderKey>);

impl CoverageVector {
    /// Whether `key` is at or below this device's claim for `key`'s origin.
    /// Ops that answer `true` are served positionally, not on channel A.
    pub fn covers(&self, key: &OrderKey) -> bool {
        self.0.get(&key.device).is_some_and(|claim| *key <= *claim)
    }
}

/// `app_config` flag set once the origin index exists and every origin has a
/// primed claim.
pub const COVERAGE_PRIMED_KEY: &str = "mesh.origin_coverage_primed";

/// The channel-A index. Deliberately absent from the v84 migration — building
/// it over a ~25M-row oplog would block boot — and created by the background
/// priming task instead.
pub const ORIGIN_INDEX_DDL: &str =
    "CREATE INDEX IF NOT EXISTS oplog_db.idx_oplog_origin ON oplog(device_id, hlc, op_id)";

const ORIGIN_INDEX_NAME: &str = "idx_oplog_origin";

/// Whether this device may speak v3: the flag is set AND `idx_oplog_origin`
/// exists.
///
/// The index check is not belt-and-braces. `app_config` is out of local
/// emission scope but rows for it CAN arrive as remote signed ops, and a
/// merged snapshot imports the serving device's rows wholesale — so the flag
/// alone can be true on a device that never built the index or primed a single
/// claim.
pub fn is_primed(conn: &rusqlite::Connection) -> Result<bool, GCError> {
    let flag: Option<String> = conn
        .prepare_cached("SELECT value FROM app_config WHERE key = ?1")
        .and_then(|mut stmt| {
            stmt.query_row(params![COVERAGE_PRIMED_KEY], |row| row.get(0))
                .optional()
        })
        .map_err(|e| GCError::Other(format!("coverage primed flag: {e}")))?;
    if flag.as_deref() != Some("1") {
        return Ok(false);
    }
    origin_index_exists(conn)
}

fn origin_index_exists(conn: &rusqlite::Connection) -> Result<bool, GCError> {
    conn.prepare_cached("SELECT 1 FROM oplog_db.sqlite_master WHERE type = 'index' AND name = ?1")
        .and_then(|mut stmt| {
            stmt.query_row(params![ORIGIN_INDEX_NAME], |_| Ok(()))
                .optional()
        })
        .map(|found| found.is_some())
        .map_err(|e| GCError::Other(format!("coverage origin index lookup: {e}")))
}

/// Every claim this device holds. The request builder sends this map verbatim.
pub fn local_coverage(conn: &rusqlite::Connection) -> Result<CoverageVector, GCError> {
    let mut stmt = conn
        .prepare_cached("SELECT origin_device_id, coverage FROM oplog_db.mesh_origin_coverage")
        .map_err(|e| GCError::Other(format!("local coverage prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| GCError::Other(format!("local coverage query: {e}")))?;
    let mut vector = BTreeMap::new();
    for row in rows {
        let (origin, wire) = row.map_err(|e| GCError::Other(format!("local coverage row: {e}")))?;
        let (Ok(origin), Ok(wire)) = (
            <[u8; 32]>::try_from(origin.as_slice()),
            <[u8; 72]>::try_from(wire.as_slice()),
        ) else {
            continue;
        };
        vector.insert(DeviceId::from_bytes(origin), OrderKey::from_wire(&wire));
    }
    Ok(CoverageVector(vector))
}

/// Raise this device's claim for `origin` to `key`, never lowering it. The
/// stored form is the 72-byte big-endian `OrderKey` wire encoding, so the
/// `<` in the conflict clause IS the order-key comparison (the same trick
/// `oplog::save_cursor` uses).
pub fn advance_local_coverage(
    conn: &rusqlite::Connection,
    origin: &DeviceId,
    key: OrderKey,
) -> Result<(), GCError> {
    conn.prepare_cached(
        "INSERT INTO oplog_db.mesh_origin_coverage (origin_device_id, coverage, updated_at)
         VALUES (?1, ?2, datetime('now'))
         ON CONFLICT(origin_device_id) DO UPDATE
         SET coverage = excluded.coverage,
             updated_at = excluded.updated_at
         WHERE mesh_origin_coverage.coverage < excluded.coverage",
    )
    .and_then(|mut stmt| {
        stmt.execute(params![
            origin.as_bytes().as_slice(),
            key.to_wire().as_slice()
        ])
    })
    .map_err(|e| GCError::Other(format!("advance local coverage: {e}")))?;
    Ok(())
}

/// Fold a locally emitted op into self-coverage, inside the caller's
/// transaction. Called from [`super::oplog::append`] on `ORIGIN_LOCAL` ops
/// only: our own emissions are contiguous by construction, so the claim stays
/// true and channel A never re-serves our own history back to us.
pub fn note_own_op(conn: &rusqlite::Connection, op: &SignedOp) -> Result<(), GCError> {
    advance_local_coverage(
        conn,
        &op.body.device,
        OrderKey {
            hlc: op.body.hlc,
            device: op.body.device,
            op_id: op.id,
        },
    )
}

/// Origins primed per write transaction. Small enough that a live writer never
/// waits long, large enough that a wide fleet primes in a handful of commits.
pub const PRIME_CHUNK: usize = 64;

/// Block until `landed` is set, or until `max` elapses.
///
/// Returns whether the flag actually landed. The bound is the point: a root
/// with no peers never sweeps, and it must still get its origin index.
pub fn wait_for_trellis_sweep(
    landed: &std::sync::atomic::AtomicBool,
    max: std::time::Duration,
    poll: std::time::Duration,
) -> bool {
    let started = std::time::Instant::now();
    loop {
        if landed.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }
        if started.elapsed() >= max {
            return false;
        }
        std::thread::sleep(poll);
    }
}

/// Build `idx_oplog_origin` if absent, set each origin's claim to that
/// origin's maximum order key in the local log, then set the primed flag.
/// Idempotent: re-running is a MAX-fold that changes nothing. Returns the
/// number of origins primed.
///
/// Runs from a background `spawn_blocking` task, never from a migration: the
/// `CREATE INDEX` is the expensive step and boot must not wait on it.
pub fn ensure_origin_index(conn: &rusqlite::Connection) -> Result<bool, GCError> {
    if !origin_index_exists(conn)? {
        conn.execute_batch(ORIGIN_INDEX_DDL)
            .map_err(|e| GCError::Other(format!("create origin index: {e}")))?;
        return Ok(true);
    }
    Ok(false)
}

pub fn list_distinct_origins(conn: &rusqlite::Connection) -> Result<Vec<crate::DeviceId>, GCError> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT device_id FROM oplog_db.oplog")
        .map_err(|e| GCError::Other(format!("coverage origins prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|e| GCError::Other(format!("coverage origins query: {e}")))?;
    let mut origins = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| GCError::Other(format!("coverage origins row: {e}")))?;
        if let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice()) {
            origins.push(DeviceId::from_bytes(id));
        }
    }
    Ok(origins)
}

pub fn prime_origins_chunk_in_txn(
    conn: &rusqlite::Connection,
    chunk: &[crate::DeviceId],
) -> Result<usize, GCError> {
    let mut primed = 0usize;
    for origin in chunk {
        let Some(key) = origin_max(conn, origin)? else {
            continue;
        };
        advance_local_coverage(conn, origin, key)?;
        primed += 1;
    }
    Ok(primed)
}

pub fn mark_coverage_primed(conn: &rusqlite::Connection) -> Result<(), GCError> {
    conn.execute(
        "INSERT INTO app_config (key, value, updated_at)
         VALUES (?1, '1', datetime('now'))
         ON CONFLICT(key) DO UPDATE
         SET value = excluded.value, updated_at = excluded.updated_at",
        params![COVERAGE_PRIMED_KEY],
    )
    .map_err(|e| GCError::Other(format!("set coverage primed flag: {e}")))?;
    Ok(())
}

/// One origin's highest order key. `device_id` is fixed, so the remaining
/// `hlc DESC, op_id DESC` ordering rides `idx_oplog_origin` as a single
/// reverse seek.
fn origin_max(conn: &rusqlite::Connection, origin: &DeviceId) -> Result<Option<OrderKey>, GCError> {
    conn.query_row(
        "SELECT hlc, device_id, op_id FROM oplog_db.oplog INDEXED BY idx_oplog_origin
         WHERE device_id = ?1
         ORDER BY hlc DESC, op_id DESC
         LIMIT 1",
        params![origin.as_bytes().as_slice()],
        |row| {
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
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Blob,
                    "op id".into(),
                )
            })?;
            Ok(OrderKey {
                hlc: Hlc(hlc as u64),
                device: DeviceId::from_bytes(device),
                op_id: OpId::from_bytes(op_id),
            })
        },
    )
    .optional()
    .map_err(|e| GCError::Other(format!("coverage origin max: {e}")))
}

/// Record the channel-B cursor a pulling peer presented. The presentation is
/// only meaningful against the epoch it was made in, so a request carrying any
/// epoch but this relay's current one is ignored outright; within the current
/// epoch the ack MAX-folds, and a row still holding a rotated-away epoch is
/// replaced rather than folded.
///
/// `updated_at` moves when the ack advances or the peer presents the relay
/// head. A peer re-presenting a cursor below the head stops pinning after the TTL.
pub fn record_peer_ack(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    epoch: &[u8; 32],
    seq: u64,
) -> Result<(), GCError> {
    let stream = super::oplog::relay_stream_state(conn)?;
    if stream.stream_epoch != *epoch {
        return Ok(());
    }
    let to_i64 = |value: u64| {
        i64::try_from(value)
            .map_err(|_| GCError::InvalidArgument("peer ack exceeds SQLite range".into()))
    };
    let (seq, head) = (to_i64(seq)?, to_i64(stream.head_seq)?);
    conn.prepare_cached(
        "INSERT INTO oplog_db.mesh_peer_acks (peer_device_id, stream_epoch, acked_relay_seq, updated_at)
         VALUES (?1, ?2, ?3, datetime('now'))
         ON CONFLICT(peer_device_id) DO UPDATE
         SET acked_relay_seq = CASE
                 WHEN mesh_peer_acks.stream_epoch = excluded.stream_epoch
                 THEN MAX(mesh_peer_acks.acked_relay_seq, excluded.acked_relay_seq)
                 ELSE excluded.acked_relay_seq
             END,
             updated_at = CASE
                 WHEN mesh_peer_acks.stream_epoch != excluded.stream_epoch
                   OR excluded.acked_relay_seq > mesh_peer_acks.acked_relay_seq
                   OR excluded.acked_relay_seq >= ?4
                 THEN excluded.updated_at
                 ELSE mesh_peer_acks.updated_at
             END,
             stream_epoch = excluded.stream_epoch",
    )
    .and_then(|mut stmt| stmt.execute(params![peer.as_bytes().as_slice(), epoch.as_slice(), seq, head]))
    .map_err(|e| GCError::Other(format!("record peer ack: {e}")))?;
    Ok(())
}

/// Whether [`record_peer_ack`] for `seq` would only rewrite a row already in
/// `epoch`, at or past `seq`, and under an hour old. Compaction drops a row
/// that goes `PEER_ACK_TTL` without a write, so an unchanged cursor is still
/// rewritten hourly. Keep this in step with the upsert above.
pub fn peer_ack_is_current(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    epoch: &[u8; 32],
    seq: u64,
) -> Result<bool, GCError> {
    let Ok(seq) = i64::try_from(seq) else {
        return Ok(false);
    };
    conn.prepare_cached(
        "SELECT EXISTS (
             SELECT 1 FROM oplog_db.mesh_peer_acks
             WHERE peer_device_id = ?1 AND stream_epoch = ?2 AND acked_relay_seq >= ?3
               AND updated_at >= datetime('now', '-1 hour'))",
    )
    .and_then(|mut stmt| {
        stmt.query_row(
            params![peer.as_bytes().as_slice(), epoch.as_slice(), seq],
            |row| row.get(0),
        )
    })
    .map_err(|e| GCError::Other(format!("read peer ack: {e}")))
}

/// This relay's current stream epoch.
pub fn current_stream_epoch(conn: &rusqlite::Connection) -> Result<[u8; 32], GCError> {
    let epoch: Vec<u8> = conn
        .prepare_cached("SELECT stream_epoch FROM oplog_db.mesh_relay_state WHERE singleton = 1")
        .and_then(|mut stmt| stmt.query_row([], |row| row.get(0)))
        .map_err(|e| GCError::Other(format!("current stream epoch: {e}")))?;
    <[u8; 32]>::try_from(epoch.as_slice())
        .map_err(|_| GCError::Other("relay stream epoch is not 32 bytes".into()))
}

/// The lowest channel-B position every admitted peer has durably presented for
/// `current_epoch`. A trusted peer with no row, or a row from a rotated-away
/// epoch, counts zero — so one silent or v2-only peer collapses the term and
/// leaves compaction on the horizon rule alone.
///
/// A peer with no current-epoch row whose `last_seen_at` predates
/// `dormant_before` is a dead pairing, not a slow one: it is excluded from
/// the floor entirely rather than pinning retention at zero forever. The
/// moment it pulls again it re-enters both `last_seen_at` and the ack table.
///
/// `None` when no trusted peer exists besides us — or when every trusted
/// peer is a dormant pairing — mirroring the peer-count guard in
/// `retention::safe_relay_floor`: the horizon rule alone governs.
pub fn min_peer_ack(
    conn: &rusqlite::Connection,
    local_device: &DeviceId,
    current_epoch: &[u8; 32],
    dormant_before: Option<&str>,
) -> Result<Option<u64>, GCError> {
    min_peer_ack_with_ttl(conn, local_device, current_epoch, dormant_before, None)
}

pub fn min_peer_ack_with_ttl(
    conn: &rusqlite::Connection,
    local_device: &DeviceId,
    current_epoch: &[u8; 32],
    dormant_before: Option<&str>,
    ack_cutoff_secs: Option<i64>,
) -> Result<Option<u64>, GCError> {
    let peers = {
        let mut stmt = conn
            .prepare(
                "SELECT device_id, first_seen_at, last_seen_at FROM devices
                 WHERE trusted = 1 AND device_id != ?1
                   AND COALESCE(introduced_by, '') != 'local-history'",
            )
            .map_err(|e| GCError::Other(format!("peer ack peers prepare: {e}")))?;
        let rows = stmt
            .query_map(params![local_device.to_hex()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| GCError::Other(format!("peer ack peers query: {e}")))?;
        let mut peers = Vec::new();
        for row in rows {
            peers.push(row.map_err(|e| GCError::Other(format!("peer ack peers row: {e}")))?);
        }
        peers
    };
    if peers.is_empty() {
        return Ok(None);
    }

    let mut stmt = conn
        .prepare(
            "SELECT acked_relay_seq, CAST(strftime('%s', updated_at) AS INTEGER),
                    stream_epoch = ?2
             FROM oplog_db.mesh_peer_acks
             WHERE peer_device_id = ?1",
        )
        .map_err(|e| GCError::Other(format!("peer ack prepare: {e}")))?;
    let mut floor = u64::MAX;
    for (peer, first_seen_at, last_seen_at) in &peers {
        let Ok(peer) = DeviceId::from_hex(peer) else {
            return Ok(Some(0));
        };
        let ack: Option<(i64, Option<i64>, bool)> = stmt
            .query_row(
                params![peer.as_bytes().as_slice(), current_epoch.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| GCError::Other(format!("peer ack lookup: {e}")))?;
        let unseen = dormant_before.is_some_and(|cutoff| last_seen_at.as_str() < cutoff);
        let (acked, updated_secs) = match ack {
            Some((acked, updated_secs, true)) => (acked, updated_secs),
            // Acked a rotated-away epoch: the peer keeps the floor at 0 until it
            // re-acks, but only while that last ack is inside the TTL. A peer
            // that stays visible yet never acks the new epoch stops pinning.
            Some((_, updated_secs, false)) => {
                let expired = ack_cutoff_secs
                    .is_some_and(|cutoff| updated_secs.is_some_and(|ts| ts < cutoff));
                if unseen || expired {
                    continue;
                }
                return Ok(Some(0));
            }
            // Never acked anything: a newly paired peer gets one TTL to start.
            None => {
                let overdue = ack_cutoff_secs.is_some()
                    && dormant_before.is_some_and(|cutoff| first_seen_at.as_str() < cutoff);
                if unseen || overdue {
                    continue;
                }
                return Ok(Some(0));
            }
        };
        if let Some(cutoff_secs) = ack_cutoff_secs {
            if updated_secs.is_some_and(|ts| ts < cutoff_secs) {
                continue;
            }
        }
        if unseen
            && ack_cutoff_secs
                .is_none_or(|cutoff_secs| updated_secs.is_none_or(|ts| ts < cutoff_secs))
        {
            continue;
        }
        floor = floor.min(acked.max(0) as u64);
        if floor == 0 {
            return Ok(Some(0));
        }
    }
    if floor == u64::MAX {
        return Ok(None);
    }
    Ok(Some(floor))
}

/// Every origin device present in the local log, ascending by raw device-id
/// bytes — the order channel A walks, so a resume token identifies a position
/// in a stable sequence.
///
/// Skip-scan, not `SELECT DISTINCT`: SQLite has no distinct-enumeration
/// optimization, so the plain form walks every row of `idx_oplog_origin` —
/// seconds of CPU and a flushed page cache on a 25M-row log, on every served
/// v3 page. The recursive form probes `idx_oplog_origin` once per origin
/// instead, so the cost tracks the number of devices, not the size of the log.
pub fn origins(conn: &rusqlite::Connection) -> Result<Vec<DeviceId>, GCError> {
    let mut stmt = conn
        .prepare_cached(
            "WITH RECURSIVE o(d) AS (
                 SELECT MIN(device_id) FROM oplog_db.oplog
                 UNION ALL
                 SELECT (SELECT MIN(device_id) FROM oplog_db.oplog WHERE device_id > d)
                 FROM o WHERE d IS NOT NULL
             )
             SELECT d FROM o WHERE d IS NOT NULL",
        )
        .map_err(|e| GCError::Other(format!("oplog origins prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|e| GCError::Other(format!("oplog origins query: {e}")))?;
    let mut origins = Vec::new();
    for row in rows {
        let bytes = row.map_err(|e| GCError::Other(format!("oplog origins row: {e}")))?;
        if let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice()) {
            origins.push(DeviceId::from_bytes(id));
        }
    }
    Ok(origins)
}
