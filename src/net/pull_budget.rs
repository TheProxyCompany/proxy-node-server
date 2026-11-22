//! Pull page row admission and keyed pagination.
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::{MeshPullSocket, decode_order_key};
use crate::identity::{DeviceId, encode_hex};
use crate::op::OrderKey;
use crate::pull::{CoverageVector, MAX_PULL_SINGLETON_BYTES, PullPhase, Resume};

pub(super) enum Admission {
    Push(String),
    Defer,
    SkipOversized,
}

pub(super) fn admit_row<E>(
    superseded: impl FnOnce(&OrderKey) -> Result<bool, E>,
    key: OrderKey,
    envelope: &[u8],
    occupied: bool,
    bytes: &mut usize,
    budget: usize,
) -> Result<Admission, E> {
    let encoded_bytes = base64::encoded_len(envelope.len(), true).unwrap_or(usize::MAX);
    if encoded_bytes > MAX_PULL_SINGLETON_BYTES {
        if superseded(&key)? {
            return Ok(Admission::SkipOversized);
        }
        tracing::error!(origin = %key.device.to_hex(), order_key = %encode_hex(&key.to_wire()),
            op_id = %key.op_id.to_hex(), raw_bytes = envelope.len(), encoded_bytes,
            "oversized pull row has no newer head; skipping row to keep link live");
        return Ok(Admission::SkipOversized);
    }
    if occupied && encoded_bytes > budget.saturating_sub(*bytes) {
        return Ok(Admission::Defer);
    }
    *bytes += encoded_bytes;
    Ok(Admission::Push(BASE64.encode(envelope)))
}

fn encode_checked<E>(
    rows: Vec<(OrderKey, Vec<u8>)>,
    keyed: &mut Vec<String>,
    bytes: &mut usize,
    byte_budget: usize,
    superseded: impl Fn(&OrderKey) -> Result<bool, E>,
) -> Result<(usize, Option<OrderKey>), E> {
    let mut consumed = 0;
    let mut last_key = None;
    for (key, envelope) in rows {
        match admit_row(
            &superseded,
            key,
            &envelope,
            !keyed.is_empty(),
            bytes,
            byte_budget,
        )? {
            Admission::Defer => break,
            Admission::Push(row) => keyed.push(row),
            Admission::SkipOversized => {}
        }
        consumed += 1;
        last_key = Some(key);
        if *bytes >= byte_budget {
            break;
        }
    }
    Ok((consumed, last_key))
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

    let mut origins = socket.origins()?;
    if let Some(pos) = origins.iter().position(|candidate| candidate == own) {
        let own_id = origins.remove(pos);
        origins.insert(0, own_id);
    }
    let resume_origin = resume.and_then(|r| DeviceId::from_hex(&r.origin).ok());
    let resume_key = resume.and_then(|r| decode_order_key(&r.after_key));
    let start = match resume_origin {
        Some(origin) if origin == *own && origins.first() == Some(own) => 0,
        Some(origin) => {
            let offset = usize::from(origins.first() == Some(own));
            offset + origins[offset..].partition_point(|candidate| *candidate < origin)
        }
        None => 0,
    };

    let mut remaining = budget;
    for origin in &origins[start..] {
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
        let (consumed, last_key) =
            encode_checked(rows, &mut keyed, &mut bytes, byte_budget, |key| {
                socket.is_superseded(key)
            })?;
        let count_exhausted = fetched == remaining;
        remaining -= consumed;
        if count_exhausted || consumed < fetched || bytes >= byte_budget {
            let token_key = last_key.or(if resumed_here { resume_key } else { None });
            return Ok((keyed, Some(keyed_resume(origin, token_key))));
        }
    }
    Ok((keyed, None))
}
