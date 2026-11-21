//! Pull Protocol v3 server mechanics: two-channel page builder, compaction
//! acknowledgment admission, and request authentication.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::pull_client::{decode_epoch, decode_order_key};
pub use super::pull_router::{PullHandler, pull_router};
use super::socket::MeshPullSocket;
use crate::identity::{DeviceId, encode_hex};
use crate::log::RelayStreamState;
use crate::op::OrderKey;
use crate::pull::{
    CoverageVector, PULL_PAGE_BYTE_BUDGET, PULL_PAGE_LIMIT_MAX, PULL_VERSION, PullPage, PullPhase,
    PullRequest, Resume, verify_pull_request,
};

/// Mirrors `relay_needs_reset` so channel B inherits v2's epoch and floor reset semantics.
pub fn pull_needs_reset(request_epoch: [u8; 32], after: u64, state: &RelayStreamState) -> bool {
    (request_epoch == [0u8; 32] && state.floor > 0)
        || (request_epoch != [0u8; 32] && request_epoch != state.epoch)
        || (request_epoch == state.epoch && (after < state.floor || after > state.head))
}

/// Construct a reset [`PullPage`] advertising `stream`'s current epoch, floor, and head.
pub fn reset_pull_page(stream: &RelayStreamState) -> PullPage {
    PullPage {
        version: PULL_VERSION,
        epoch: encode_hex(&stream.epoch),
        reset: true,
        floor: stream.floor,
        backfill: Vec::new(),
        keyed: Vec::new(),
        next_relay_seq: 0,
        head_seq: stream.head,
        resume: None,
        complete: false,
        snapshot_recommended: false,
        store: None,
    }
}

/// Base64-encode one origin's `(OrderKey, raw_envelope)` rows into `keyed` up
/// to `byte_budget`, returning `(served_count, last_key)`.
pub fn encode_origin_rows(
    rows: Vec<(OrderKey, Vec<u8>)>,
    keyed: &mut Vec<String>,
    bytes: &mut usize,
    byte_budget: usize,
) -> (usize, Option<OrderKey>) {
    let mut served = 0usize;
    let mut last_key = None;
    for (key, envelope) in rows {
        let encoded = BASE64.encode(&envelope);
        if *bytes > 0 && *bytes + encoded.len() > byte_budget {
            break;
        }
        *bytes += encoded.len();
        keyed.push(encoded);
        last_key = Some(key);
        served += 1;
        if *bytes >= byte_budget {
            break;
        }
    }
    (served, last_key)
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
/// within an origin and origins ascending by raw device-id bytes.
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
        let (served, last_key) = encode_origin_rows(rows, &mut keyed, &mut bytes, byte_budget);
        remaining -= served;
        if remaining == 0 || served < fetched || bytes >= byte_budget {
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
        let (served, last_key) = encode_origin_rows(rows, &mut keyed, &mut bytes, byte_budget);
        let count_exhausted = fetched == remaining;
        remaining -= served;
        if count_exhausted || served < fetched || bytes >= byte_budget {
            let token_key = last_key.or(if resumed_here { resume_key } else { None });
            return Ok((keyed, Some(keyed_resume(origin, token_key))));
        }
    }
    Ok((keyed, None))
}

/// Construct a [`PullPage`] across Channel A (keyed per-origin diff) and
/// Channel B (positional arrival backfill) against `socket`.
pub fn build_pull_page<S: MeshPullSocket + ?Sized>(
    socket: &S,
    _peer: &DeviceId,
    request: &PullRequest,
) -> Result<PullPage, S::Error> {
    let stream = socket.relay_stream_state()?;
    let request_epoch = decode_epoch(&request.relay_epoch)
        .ok_or_else(|| S::invalid_argument("invalid relay epoch"))?;

    let store_filter = request.store.as_deref();
    if store_filter.is_none() && pull_needs_reset(request_epoch, request.relay_after, &stream) {
        return Ok(reset_pull_page(&stream));
    }

    let epoch_hex = encode_hex(&stream.epoch);
    let limit = request.limit.clamp(1, PULL_PAGE_LIMIT_MAX) as usize;
    let claims = CoverageVector(request.decode_coverage());
    let audit = request.audit;
    let resume_keyed = request
        .resume
        .as_ref()
        .filter(|resume| resume.phase == PullPhase::Keyed);
    let own = socket.own_device_id();

    if let Some(store) = store_filter {
        let (keyed, resume) = build_keyed_channel(
            socket,
            &claims,
            resume_keyed,
            audit,
            limit,
            PULL_PAGE_BYTE_BUDGET,
            Some(store),
            &own,
        )?;
        return Ok(PullPage {
            version: PULL_VERSION,
            epoch: epoch_hex,
            reset: false,
            floor: stream.floor,
            backfill: Vec::new(),
            keyed,
            next_relay_seq: request.relay_after,
            complete: resume.is_none(),
            resume,
            snapshot_recommended: false,
            head_seq: stream.head,
            store: Some(store.to_string()),
        });
    }

    let start_seq = match &request.resume {
        Some(resume) if resume.phase == PullPhase::Backfill => resume.after_seq,
        Some(_) | None => request.relay_after,
    };

    let mut next_relay_seq = start_seq;
    let page = |backfill: Vec<(u64, String)>,
                keyed: Vec<String>,
                next_relay_seq: u64,
                resume: Option<Resume>| PullPage {
        version: PULL_VERSION,
        epoch: epoch_hex.clone(),
        reset: false,
        floor: stream.floor,
        backfill,
        keyed,
        next_relay_seq,
        complete: resume.is_none(),
        resume,
        snapshot_recommended: false,
        head_seq: stream.head,
        store: None,
    };
    let backfill_resume = |after_seq: u64| Resume {
        phase: PullPhase::Backfill,
        after_seq,
        origin: String::new(),
        after_key: String::new(),
    };

    let resume_backfill =
        matches!(&request.resume, Some(resume) if resume.phase == PullPhase::Backfill);
    let backfill_pending = request.relay_after < stream.head || start_seq < stream.head;
    let mut budget = limit;
    let mut keyed = Vec::new();
    let mut pending_keyed_resume = None;
    if !resume_backfill {
        let keyed_budget = if backfill_pending {
            ((limit * 3) / 4).max(1)
        } else {
            limit
        };
        let keyed_byte_budget = if backfill_pending {
            (PULL_PAGE_BYTE_BUDGET * 3) / 4
        } else {
            PULL_PAGE_BYTE_BUDGET
        };
        let (served, keyed_resume) = build_keyed_channel(
            socket,
            &claims,
            resume_keyed,
            audit,
            keyed_budget,
            keyed_byte_budget,
            None,
            &own,
        )?;
        keyed = served;
        pending_keyed_resume = keyed_resume;
        budget = limit.saturating_sub(keyed.len());
        if budget == 0 {
            let resume = pending_keyed_resume.or_else(|| Some(backfill_resume(start_seq)));
            return Ok(page(Vec::new(), keyed, next_relay_seq, resume));
        }
    }

    let mut backfill = Vec::new();
    let mut page_bytes: usize = keyed.iter().map(String::len).sum();
    let mut byte_cut = false;
    let mut scanned_len = 0usize;
    if budget > 0 && page_bytes < PULL_PAGE_BYTE_BUDGET {
        let scanned = socket.relay_since_with_envelopes(start_seq, budget)?;
        scanned_len = scanned.len();
        for (seq, op, envelope) in scanned {
            if byte_cut && claims.covers(&op.order_key()) {
                break;
            }
            if claims.covers(&op.order_key()) {
                let encoded = BASE64.encode(&envelope);
                if page_bytes > 0 && page_bytes + encoded.len() > PULL_PAGE_BYTE_BUDGET {
                    byte_cut = true;
                    break;
                }
                page_bytes += encoded.len();
                backfill.push((seq, encoded));
                byte_cut = page_bytes >= PULL_PAGE_BYTE_BUDGET;
            }
            next_relay_seq = seq;
        }
    }
    let resume = pending_keyed_resume.or_else(|| {
        ((scanned_len == budget && budget > 0) || byte_cut).then(|| backfill_resume(next_relay_seq))
    });
    Ok(page(backfill, keyed, next_relay_seq, resume))
}

/// Validate and record a presented compaction acknowledgment against `socket`.
pub fn admit_pull_ack<S: MeshPullSocket + ?Sized>(
    socket: &S,
    peer: &DeviceId,
    request: &PullRequest,
) -> Result<Option<PullPage>, S::Error> {
    let request_epoch = decode_epoch(&request.relay_epoch)
        .ok_or_else(|| S::invalid_argument("invalid relay epoch"))?;
    let stream = socket.relay_stream_state()?;
    if pull_needs_reset(request_epoch, request.relay_after, &stream) {
        return Ok(Some(reset_pull_page(&stream)));
    }
    if request_epoch == [0u8; 32] {
        return Ok(None);
    }
    socket.record_peer_ack(peer, &request_epoch, request.relay_after)?;
    Ok(None)
}

/// Map a [`verify_pull_request`] error string to the canonical HTTP status code.
pub fn classify_pull_request_error(message: &str) -> StatusCode {
    if message.starts_with("Invalid payload:") || message == "Unsupported pull protocol version" {
        StatusCode::BAD_REQUEST
    } else if message == "Pull request expired" {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    }
}

/// Verify a signed pull request envelope against `socket`.
pub fn authenticate_pull_request<S: MeshPullSocket + ?Sized>(
    socket: &S,
    bytes: &[u8],
) -> Result<(DeviceId, PullRequest), (StatusCode, String)> {
    let mut lookup_error: Option<String> = None;
    let (peer, request) = verify_pull_request(bytes, socket.now_ms(), |peer| {
        match socket.lookup_peer_sec1(peer) {
            Ok(key) => Ok(key),
            Err(error) => {
                let msg = error.to_string();
                lookup_error = Some(msg.clone());
                Err(msg)
            }
        }
    })
    .map_err(|message| {
        if let Some(error) = lookup_error {
            return (StatusCode::INTERNAL_SERVER_ERROR, error);
        }
        (classify_pull_request_error(&message), message)
    })?;

    match socket.is_peer_trusted(&peer) {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::FORBIDDEN,
                "Pull requester is not a trusted device".to_string(),
            ));
        }
        Err(error) => return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
    }
    match socket.is_coverage_primed() {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Origin coverage is still priming".to_string(),
            ));
        }
        Err(error) => return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
    }
    Ok((peer, request))
}
