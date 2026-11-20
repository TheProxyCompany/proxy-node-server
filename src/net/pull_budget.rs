//! Pull page row admission and keyed pagination.
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::{MeshPullSocket, decode_order_key};
use crate::identity::{DeviceId, encode_hex};
use crate::op::OrderKey;
use crate::pull::{CoverageVector, PULL_SINGLETON_ROW_MAX_BYTES, PullPhase, Resume};

pub(super) enum Admission {
    Push(String),
    Defer,
    Quarantine,
}

pub(super) fn admit_row(
    key: OrderKey,
    envelope: &[u8],
    occupied: bool,
    bytes: &mut usize,
    budget: usize,
) -> Admission {
    let encoded_bytes = base64::encoded_len(envelope.len(), true).unwrap_or(usize::MAX);
    if encoded_bytes > PULL_SINGLETON_ROW_MAX_BYTES {
        tracing::warn!(origin = %key.device.to_hex(), order_key = %encode_hex(&key.to_wire()),
            op_id = %key.op_id.to_hex(), raw_bytes = envelope.len(), encoded_bytes,
            "oversized pull row quarantined at source; skipping row");
        return Admission::Quarantine;
    }
    if occupied && encoded_bytes > budget.saturating_sub(*bytes) {
        return Admission::Defer;
    }
    *bytes += encoded_bytes;
    Admission::Push(BASE64.encode(envelope))
}

/// Append admissible rows, returning the number consumed and the last consumed key.
pub fn encode_origin_rows(
    rows: Vec<(OrderKey, Vec<u8>)>,
    keyed: &mut Vec<String>,
    bytes: &mut usize,
    byte_budget: usize,
) -> (usize, Option<OrderKey>) {
    let mut consumed = 0;
    let mut last_key = None;
    for (key, envelope) in rows {
        match admit_row(key, &envelope, !keyed.is_empty(), bytes, byte_budget) {
            Admission::Defer => break,
            Admission::Push(row) => keyed.push(row),
            Admission::Quarantine => {}
        }
        consumed += 1;
        last_key = Some(key);
        if *bytes >= byte_budget {
            break;
        }
    }
    (consumed, last_key)
}

/// Build a [`PullPhase::Keyed`] resume token positioned at `(origin, last_key)`.
pub fn keyed_resume(origin: &DeviceId, last_key: Option<OrderKey>) -> Resume {
    Resume {
        phase: PullPhase::Keyed,
        after_seq: 0,
        origin: origin.to_hex(),
        after_key: last_key
            .map(|key| encode_hex(&key.to_wire()))
            .unwrap_or_default(),
    }
}

/// Channel A: each origin's ops strictly above the puller's claim, ascending
/// within an origin and origins ascending by raw device-id bytes (with the
/// serving device's own origin fronted on a fresh exchange).
#[allow(clippy::too_many_arguments)]
pub fn build_keyed_channel<S: MeshPullSocket + ?Sized>(
    socket: &S,
    claims: &CoverageVector,
    resume: Option<&Resume>,
    audit: bool,
    budget: usize,
    byte_budget: usize,
    store: Option<&str>,
    own: &DeviceId,
) -> Result<(Vec<String>, Option<Resume>), S::Error> {
    let mut keyed = Vec::new();
    let mut bytes: usize = 0;
    if budget == 0 {
        return Ok((keyed, resume.cloned()));
    }

    let origins = socket.origins()?;
    let resume_origin = resume.and_then(|r| DeviceId::from_hex(&r.origin).ok());
    let resume_key = resume.and_then(|r| decode_order_key(&r.after_key));
    let start = match resume_origin {
        Some(origin) => origins.partition_point(|candidate| *candidate < origin),
        None => 0,
    };

    let mut remaining = budget;
    let mut own_served_first = false;
    if resume.is_none() && origins.contains(own) {
        own_served_first = true;
        let claim = if audit {
            None
        } else {
            claims.0.get(own).copied()
        };
        let rows = socket.origin_since(own, claim, store, remaining)?;
        let fetched = rows.len();
        let (consumed, last_key) = encode_origin_rows(rows, &mut keyed, &mut bytes, byte_budget);
        remaining -= consumed;
        if remaining == 0 || consumed < fetched || bytes >= byte_budget {
            return Ok((keyed, Some(keyed_resume(own, last_key))));
        }
    }
    for origin in &origins[start..] {
        if own_served_first && origin == own {
            continue;
        }
        let resumed_here = resume_origin == Some(*origin);
        let claim = if audit {
            None
        } else {
            claims.0.get(origin).copied()
        };
        let after = match (claim, if resumed_here { resume_key } else { None }) {
            (Some(claim), Some(resume_key)) => Some(claim.max(resume_key)),
            (Some(claim), None) => Some(claim),
            (None, resume_key) => resume_key,
        };
        let rows = socket.origin_since(origin, after, store, remaining)?;
        let fetched = rows.len();
        let (consumed, last_key) = encode_origin_rows(rows, &mut keyed, &mut bytes, byte_budget);
        let count_exhausted = fetched == remaining;
        remaining -= consumed;
        if count_exhausted || consumed < fetched || bytes >= byte_budget {
            return Ok((keyed, Some(keyed_resume(origin, last_key))));
        }
    }
    Ok((keyed, None))
}
