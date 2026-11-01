//! SQLite quarantine (`oplog_db.mesh_unverified_ops`) and verified-op provenance
//! (`oplog_db.mesh_verified_ops`) storage for mesh pull admission.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use rusqlite::{params, params_from_iter};
use sha2::{Digest, Sha256};

use super::SqliteError;
use crate::identity::{DeviceId, encode_hex};
use crate::op::SignedOp;
use crate::row_op::ORIGIN_LOCAL;

pub const MAX_QUARANTINED_OPS: i64 = 250_000;
pub const MAX_QUARANTINED_OPS_PER_PEER: i64 = 50_000;
pub const MAX_QUARANTINE_BYTES: i64 = 2 * 1024 * 1024 * 1024;
pub const MAX_QUARANTINE_BYTES_PER_PEER: i64 = 512 * 1024 * 1024;
pub const MAX_QUARANTINED_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_INVALID_QUARANTINE_AUDIT_ROWS: i64 = 10_000;
pub const MAX_INVALID_QUARANTINE_ENVELOPE_BYTES: i64 = 4 * 1024;
pub const QUARANTINE_REPLAY_BYTE_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QuarantineWriteReport {
    pub inserted: usize,
    pub total: i64,
}

#[derive(Default, Debug, Clone)]
pub struct QuarantineReplayReport {
    pub scanned: usize,
    pub applied: usize,
    pub already_applied: usize,
    pub retained_out_of_scope: usize,
    pub waiting_for_attestation: usize,
    pub retained_with_error: usize,
}

#[derive(Default)]
pub struct QuarantineReplayCadence {
    last_attempt: Option<Instant>,
    pub follow_up_due: bool,
}

impl QuarantineReplayCadence {
    pub fn due(&self, attestation_refreshed: bool, rescan_interval: Duration) -> bool {
        attestation_refreshed
            || self.follow_up_due
            || self
                .last_attempt
                .is_none_or(|last| last.elapsed() >= rescan_interval)
    }

    pub fn record_attempt(&mut self, applied: usize) {
        self.last_attempt = Some(Instant::now());
        self.follow_up_due = applied > 0;
    }
}

#[derive(Debug, Clone)]
pub struct QuarantinedRow {
    pub candidate_id: Vec<u8>,
    pub claimed_op_id: Vec<u8>,
    pub envelope: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct QuarantineReplayError {
    pub candidate_id: Vec<u8>,
    pub message: String,
    pub terminal: bool,
}

static REPORTED_UNATTESTED_SIGNERS: OnceLock<Mutex<HashSet<(String, String)>>> = OnceLock::new();

pub fn encode_quarantined_candidates<'a>(
    skipped: &[&'a SignedOp],
) -> Result<Vec<(&'a SignedOp, [u8; 32], Vec<u8>)>, SqliteError> {
    skipped
        .iter()
        .map(|op| {
            let envelope = op
                .to_bytes()
                .map_err(|error| SqliteError::Other(format!("encode quarantined op: {error}")))?;
            if envelope.len() > MAX_QUARANTINED_ENVELOPE_BYTES {
                return Err(SqliteError::Other(format!(
                    "unverified envelope is {} bytes; limit is {}; cursor held",
                    envelope.len(),
                    MAX_QUARANTINED_ENVELOPE_BYTES
                )));
            }
            let candidate_id: [u8; 32] = Sha256::digest(&envelope).into();
            Ok((*op, candidate_id, envelope))
        })
        .collect()
}

pub fn quarantine_ops(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    envelopes: &[(&SignedOp, [u8; 32], Vec<u8>)],
    now: &str,
) -> Result<QuarantineWriteReport, SqliteError> {
    let mut inserted = 0usize;
    for (op, candidate_id, envelope) in envelopes {
        inserted += conn
            .execute(
                "INSERT OR IGNORE INTO oplog_db.mesh_unverified_ops (
                    candidate_id, claimed_op_id, signer_device_id,
                    source_peer_id, envelope, envelope_bytes, first_seen,
                    last_seen, attempts, last_error, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 0, NULL, 'pending')",
                params![
                    candidate_id.as_slice(),
                    op.id.as_bytes().as_slice(),
                    op.body.device.as_bytes().as_slice(),
                    peer.as_bytes().as_slice(),
                    envelope,
                    envelope.len() as i64,
                    now,
                ],
            )
            .map_err(|error| SqliteError::Other(format!("quarantine mesh op: {error}")))?;
        conn.execute(
            "UPDATE oplog_db.mesh_unverified_ops
             SET last_seen = ?3
             WHERE candidate_id = ?1 AND source_peer_id = ?2",
            params![candidate_id.as_slice(), peer.as_bytes().as_slice(), now],
        )
        .map_err(|error| SqliteError::Other(format!("refresh quarantined mesh op: {error}")))?;
    }
    let (total, total_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(envelope_bytes), 0)
             FROM oplog_db.mesh_unverified_ops
             WHERE state != 'invalid'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| SqliteError::Other(format!("count quarantined mesh ops: {error}")))?;
    let (peer_total, peer_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(envelope_bytes), 0)
             FROM oplog_db.mesh_unverified_ops
             WHERE source_peer_id = ?1 AND state != 'invalid'",
            [peer.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| SqliteError::Other(format!("count peer quarantined mesh ops: {error}")))?;
    if total > MAX_QUARANTINED_OPS
        || total_bytes > MAX_QUARANTINE_BYTES
        || peer_total > MAX_QUARANTINED_OPS_PER_PEER
        || peer_bytes > MAX_QUARANTINE_BYTES_PER_PEER
    {
        return Err(SqliteError::Other(format!(
            "mesh unverified-op quarantine capacity reached: total={total} \
             bytes={total_bytes} peer_total={peer_total} peer_bytes={peer_bytes}; cursor held"
        )));
    }
    Ok(QuarantineWriteReport { inserted, total })
}

pub fn new_unattested_signers(peer: &DeviceId, skipped: &[&SignedOp]) -> Vec<String> {
    let signers = skipped
        .iter()
        .map(|op| op.body.device.to_hex())
        .collect::<HashSet<_>>();
    let reported = REPORTED_UNATTESTED_SIGNERS.get_or_init(|| Mutex::new(HashSet::new()));
    match reported.lock() {
        Ok(mut reported) => signers
            .into_iter()
            .filter(|signer| reported.insert((peer.to_hex(), signer.clone())))
            .collect(),
        Err(_) => Vec::new(),
    }
}

pub fn quarantined_rows(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    limit: usize,
    globally_trusted_only: bool,
) -> Result<Vec<QuarantinedRow>, SqliteError> {
    let mut stmt = conn
        .prepare(
            "SELECT quarantine.candidate_id, quarantine.claimed_op_id, quarantine.envelope
             FROM oplog_db.mesh_unverified_ops AS quarantine
             WHERE quarantine.source_peer_id = ?1 AND quarantine.state != 'invalid'
               AND (?3 = 0 OR EXISTS (
                   SELECT 1 FROM main.devices AS device
                   WHERE device.device_id = lower(hex(quarantine.signer_device_id))
                     AND device.trusted = 1
               ))
             ORDER BY quarantine.attempts ASC, quarantine.first_seen ASC
             LIMIT ?2",
        )
        .map_err(|error| SqliteError::Other(format!("prepare quarantined mesh replay: {error}")))?;
    let rows = stmt
        .query_map(
            params![
                peer.as_bytes().as_slice(),
                limit as i64,
                globally_trusted_only as i64
            ],
            |row| {
                Ok(QuarantinedRow {
                    candidate_id: row.get(0)?,
                    claimed_op_id: row.get(1)?,
                    envelope: row.get(2)?,
                })
            },
        )
        .map_err(|error| SqliteError::Other(format!("query quarantined mesh replay: {error}")))?;
    let mut selected = Vec::new();
    let mut selected_bytes = 0usize;
    for row in rows {
        let row = row.map_err(|error| {
            SqliteError::Other(format!("read quarantined mesh replay: {error}"))
        })?;
        if !selected.is_empty()
            && selected_bytes.saturating_add(row.envelope.len()) > QUARANTINE_REPLAY_BYTE_LIMIT
        {
            break;
        }
        selected_bytes = selected_bytes.saturating_add(row.envelope.len());
        selected.push(row);
    }
    Ok(selected)
}

pub fn finish_quarantine_replay(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    scanned: &[Vec<u8>],
    applied: &[Vec<u8>],
    out_of_scope: &[Vec<u8>],
    errors: &[QuarantineReplayError],
) -> Result<(), SqliteError> {
    for op_id in scanned {
        conn.execute(
            "UPDATE oplog_db.mesh_unverified_ops
             SET attempts = attempts + 1,
                 state = CASE WHEN state = 'out_of_scope' THEN 'pending' ELSE state END
             WHERE candidate_id = ?1 AND source_peer_id = ?2",
            params![op_id, peer.as_bytes().as_slice()],
        )
        .map_err(|error| {
            SqliteError::Other(format!("advance quarantined mesh attempt: {error}"))
        })?;
    }
    for error in errors {
        conn.execute(
            "UPDATE oplog_db.mesh_unverified_ops
             SET last_error = ?3,
                 state = CASE WHEN ?4 THEN 'invalid' ELSE state END
             WHERE candidate_id = ?1 AND source_peer_id = ?2",
            params![
                error.candidate_id.as_slice(),
                peer.as_bytes().as_slice(),
                &error.message,
                error.terminal,
            ],
        )
        .map_err(|error| SqliteError::Other(format!("record quarantined mesh error: {error}")))?;
    }
    conn.execute(
        "UPDATE oplog_db.mesh_unverified_ops
         SET envelope = substr(envelope, 1, ?1),
             envelope_bytes = MIN(envelope_bytes, ?1)
         WHERE state = 'invalid' AND envelope_bytes > ?1",
        [MAX_INVALID_QUARANTINE_ENVELOPE_BYTES],
    )
    .map_err(|error| {
        SqliteError::Other(format!("bound invalid mesh quarantine evidence: {error}"))
    })?;
    conn.execute(
        "DELETE FROM oplog_db.mesh_unverified_ops
         WHERE state = 'invalid'
           AND rowid NOT IN (
               SELECT rowid FROM oplog_db.mesh_unverified_ops
               WHERE state = 'invalid'
               ORDER BY last_seen DESC, rowid DESC
               LIMIT ?1
           )",
        [MAX_INVALID_QUARANTINE_AUDIT_ROWS],
    )
    .map_err(|error| {
        SqliteError::Other(format!("bound invalid mesh quarantine audit rows: {error}"))
    })?;
    for candidate_id in out_of_scope {
        conn.execute(
            "UPDATE oplog_db.mesh_unverified_ops
             SET state = 'out_of_scope', last_error = NULL
             WHERE candidate_id = ?1 AND source_peer_id = ?2",
            params![candidate_id, peer.as_bytes().as_slice()],
        )
        .map_err(|error| {
            SqliteError::Other(format!("retain out-of-scope quarantined mesh op: {error}"))
        })?;
    }
    for claimed_op_id in applied {
        conn.execute(
            "DELETE FROM oplog_db.mesh_unverified_ops WHERE claimed_op_id = ?1",
            params![claimed_op_id],
        )
        .map_err(|error| {
            SqliteError::Other(format!("delete applied quarantined mesh op: {error}"))
        })?;
    }
    Ok(())
}

pub struct RemoteOpClassification {
    pub durable_exact: HashSet<Vec<u8>>,
    pub completed: HashSet<Vec<u8>>,
}

pub fn classify_remote_ops(
    conn: &rusqlite::Connection,
    ops: &[&SignedOp],
) -> Result<RemoteOpClassification, SqliteError> {
    if ops.is_empty() {
        return Ok(RemoteOpClassification {
            durable_exact: HashSet::new(),
            completed: HashSet::new(),
        });
    }
    let mut candidates = HashMap::with_capacity(ops.len());
    for op in ops {
        let envelope = op.to_bytes().map_err(|error| {
            SqliteError::Other(format!("encode completed remote op candidate: {error}"))
        })?;
        let digest: [u8; 32] = Sha256::digest(&envelope).into();
        match candidates.entry(op.id.as_bytes().to_vec()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some((envelope, digest)));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref().map(|(bytes, _)| bytes) != Some(&envelope) {
                    entry.insert(None);
                }
            }
        }
    }
    let mut durable_exact = HashSet::with_capacity(ops.len());
    let mut completed = HashSet::with_capacity(ops.len());
    let candidate_ids = candidates.keys().collect::<Vec<_>>();
    for chunk in candidate_ids.chunks(500) {
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT oplog.op_id, oplog.envelope, oplog.origin,
                    verified.envelope_sha256
             FROM oplog_db.oplog AS oplog
             LEFT JOIN oplog_db.external_row_pending_ops AS pending
               ON pending.op_id = oplog.op_id
             LEFT JOIN oplog_db.mesh_verified_ops AS verified
               ON verified.op_id = oplog.op_id
             WHERE oplog.op_id IN ({placeholders})
               AND oplog.applied = 1
               AND oplog.origin IN (0, 1)
               AND pending.op_id IS NULL"
        );
        let mut stmt = conn.prepare(&sql).map_err(|error| {
            SqliteError::Other(format!("prepare completed remote ops: {error}"))
        })?;
        let rows = stmt
            .query_map(
                params_from_iter(chunk.iter().map(|op_id| op_id.as_slice())),
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .map_err(|error| SqliteError::Other(format!("query completed remote ops: {error}")))?;
        for row in rows {
            let (op_id, stored_envelope, origin, verified_digest) = row.map_err(|error| {
                SqliteError::Other(format!("read completed remote op: {error}"))
            })?;
            let Some(Some((candidate_envelope, candidate_digest))) =
                candidates.get(op_id.as_slice())
            else {
                continue;
            };
            let provenance_matches = origin == ORIGIN_LOCAL
                || verified_digest.as_deref() == Some(candidate_digest.as_slice());
            if candidate_envelope.as_slice() == stored_envelope.as_slice() {
                durable_exact.insert(op_id.clone());
                if provenance_matches {
                    completed.insert(op_id);
                }
            }
        }
    }
    Ok(RemoteOpClassification {
        durable_exact,
        completed,
    })
}

pub fn encode_verified_remote_ops(
    ops: &[&SignedOp],
) -> Result<Vec<(Vec<u8>, Vec<u8>, [u8; 32])>, SqliteError> {
    ops.iter()
        .map(|op| {
            let envelope = op.to_bytes().map_err(|error| {
                SqliteError::Other(format!("encode verified remote op: {error}"))
            })?;
            let digest: [u8; 32] = Sha256::digest(&envelope).into();
            Ok((op.id.as_bytes().to_vec(), envelope, digest))
        })
        .collect()
}

pub fn record_verified_ops(
    conn: &rusqlite::Connection,
    encoded: &[(Vec<u8>, Vec<u8>, [u8; 32])],
) -> Result<(), SqliteError> {
    let mut insert = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO oplog_db.mesh_verified_ops (
                 op_id, envelope_sha256
             )
             SELECT op_id, ?2 FROM oplog_db.oplog
             WHERE op_id = ?1 AND envelope = ?3",
        )
        .map_err(|error| SqliteError::Other(format!("prepare verified-op record: {error}")))?;
    let mut confirm = conn
        .prepare_cached(
            "SELECT EXISTS (
                 SELECT 1 FROM oplog_db.mesh_verified_ops
                 WHERE op_id = ?1 AND envelope_sha256 = ?2
             )",
        )
        .map_err(|error| SqliteError::Other(format!("prepare verified-op check: {error}")))?;
    for (op_id, envelope, digest) in encoded {
        insert
            .execute(params![op_id, digest.as_slice(), envelope])
            .map_err(|error| SqliteError::Other(format!("record verified remote op: {error}")))?;
        let recorded: bool = confirm
            .query_row(params![op_id, digest.as_slice()], |row| row.get(0))
            .map_err(|error| SqliteError::Other(format!("confirm verified remote op: {error}")))?;
        if !recorded {
            return Err(SqliteError::Other(format!(
                "verified remote op {} is not durably present with the verified envelope",
                encode_hex(op_id)
            )));
        }
    }
    Ok(())
}
