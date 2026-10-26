//! Pull Protocol v3 server mechanics: two-channel page builder, compaction
//! acknowledgment admission, request authentication, and the Axum router.

use std::future::Future;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::server::ServeState;
use super::socket::MeshPullSocket;
use super::v3_client::{decode_epoch, decode_order_key, unix_ms};
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity, encode_hex};
use crate::log::{LogSource, RelayStreamState};
use crate::op::OrderKey;
use crate::pull_v3::{
    CoverageVector, MAX_V3_REQUEST_BYTES, PULL_PATH, PULL_V3_VERSION, PullPageV3, PullPhase,
    PullRequestV3, ResumeV3, V3_PAGE_BYTE_BUDGET, V3_PAGE_LIMIT_MAX, seal_pull_page_v3,
    verify_pull_request_v3,
};
use crate::registry::DeviceBook;

/// Mirrors `relay_needs_reset` so channel B inherits v2's epoch and floor
/// reset semantics verbatim.
pub fn v3_needs_reset(request_epoch: [u8; 32], after: u64, state: &RelayStreamState) -> bool {
    (request_epoch == [0u8; 32] && state.floor > 0)
        || (request_epoch != [0u8; 32] && request_epoch != state.epoch)
        || (request_epoch == state.epoch && (after < state.floor || after > state.head))
}

/// Construct a reset [`PullPageV3`] advertising `stream`'s current epoch,
/// compaction floor, and head sequence.
pub fn reset_pull_page_v3(stream: &RelayStreamState) -> PullPageV3 {
    PullPageV3 {
        version: PULL_V3_VERSION,
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
pub fn keyed_resume(origin: &DeviceId, last_key: Option<OrderKey>) -> ResumeV3 {
    ResumeV3 {
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
pub fn build_keyed_channel_v3<S: MeshPullSocket + ?Sized>(
    socket: &S,
    claims: &CoverageVector,
    resume: Option<&ResumeV3>,
    audit: bool,
    budget: usize,
    byte_budget: usize,
    store: Option<&str>,
    own: &DeviceId,
) -> Result<(Vec<String>, Option<ResumeV3>), S::Error> {
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
            return Ok((keyed, Some(keyed_resume(origin, last_key))));
        }
    }
    Ok((keyed, None))
}

/// Construct a [`PullPageV3`] across Channel A (keyed per-origin diff) and
/// Channel B (positional arrival backfill) against `socket`.
pub fn build_pull_page_v3<S: MeshPullSocket + ?Sized>(
    socket: &S,
    _peer: &DeviceId,
    request: &PullRequestV3,
) -> Result<PullPageV3, S::Error> {
    let stream = socket.relay_stream_state()?;
    let request_epoch = decode_epoch(&request.relay_epoch)
        .ok_or_else(|| S::invalid_argument("invalid relay epoch"))?;

    let store_filter = request.store.as_deref();
    if store_filter.is_none() && v3_needs_reset(request_epoch, request.relay_after, &stream) {
        return Ok(reset_pull_page_v3(&stream));
    }

    let epoch_hex = encode_hex(&stream.epoch);
    let limit = request.limit.clamp(1, V3_PAGE_LIMIT_MAX) as usize;
    let claims = CoverageVector(request.decode_coverage());
    let audit = request.audit;
    let resume_keyed = request
        .resume
        .as_ref()
        .filter(|resume| resume.phase == PullPhase::Keyed);
    let own = socket.own_device_id();

    if let Some(store) = store_filter {
        let (keyed, resume) = build_keyed_channel_v3(
            socket,
            &claims,
            resume_keyed,
            audit,
            limit,
            V3_PAGE_BYTE_BUDGET,
            Some(store),
            &own,
        )?;
        return Ok(PullPageV3 {
            version: PULL_V3_VERSION,
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
                resume: Option<ResumeV3>| PullPageV3 {
        version: PULL_V3_VERSION,
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
    let backfill_resume = |after_seq: u64| ResumeV3 {
        phase: PullPhase::Backfill,
        after_seq,
        origin: String::new(),
        after_key: String::new(),
    };

    let resume_backfill =
        matches!(&request.resume, Some(resume) if resume.phase == PullPhase::Backfill);
    let mut budget = limit;
    let mut keyed = Vec::new();
    if !resume_backfill {
        let (served, keyed_resume) = build_keyed_channel_v3(
            socket,
            &claims,
            resume_keyed,
            audit,
            budget,
            V3_PAGE_BYTE_BUDGET,
            None,
            &own,
        )?;
        keyed = served;
        if keyed_resume.is_some() {
            return Ok(page(Vec::new(), keyed, next_relay_seq, keyed_resume));
        }
        budget = limit - keyed.len();
        if budget == 0 {
            return Ok(page(
                Vec::new(),
                keyed,
                next_relay_seq,
                Some(backfill_resume(start_seq)),
            ));
        }
    }

    let mut backfill = Vec::new();
    let mut page_bytes: usize = keyed.iter().map(String::len).sum();
    let mut byte_cut = false;
    let scanned = socket.relay_since_with_envelopes(start_seq, budget)?;
    let scanned_len = scanned.len();
    for (seq, op, envelope) in scanned {
        if byte_cut && claims.covers(&op.order_key()) {
            break;
        }
        next_relay_seq = seq;
        if claims.covers(&op.order_key()) {
            let encoded = BASE64.encode(&envelope);
            page_bytes += encoded.len();
            backfill.push((seq, encoded));
            byte_cut = page_bytes >= V3_PAGE_BYTE_BUDGET;
        }
    }
    let resume = ((scanned_len == budget && budget > 0) || byte_cut)
        .then(|| backfill_resume(next_relay_seq));
    Ok(page(backfill, keyed, next_relay_seq, resume))
}

/// Validate a presented compaction acknowledgment against `socket`'s current
/// stream state and record it if valid, returning `Ok(Some(reset_page))` when
/// the presented cursor requires a stream reset.
pub fn admit_pull_ack_v3<S: MeshPullSocket + ?Sized>(
    socket: &S,
    peer: &DeviceId,
    request: &PullRequestV3,
) -> Result<Option<PullPageV3>, S::Error> {
    let request_epoch = decode_epoch(&request.relay_epoch)
        .ok_or_else(|| S::invalid_argument("invalid relay epoch"))?;
    let stream = socket.relay_stream_state()?;
    if v3_needs_reset(request_epoch, request.relay_after, &stream) {
        return Ok(Some(reset_pull_page_v3(&stream)));
    }
    if request_epoch == [0u8; 32] {
        return Ok(None);
    }
    socket.record_peer_ack(peer, &request_epoch, request.relay_after)?;
    Ok(None)
}

/// Map a [`verify_pull_request_v3`] error string to the canonical HTTP status
/// code (`400 Bad Request` for malformed payload or unsupported version,
/// `403 Forbidden` for expired requests, `401 Unauthorized` otherwise).
pub fn classify_pull_request_error(message: &str) -> StatusCode {
    if message.starts_with("Invalid payload:") || message == "Unsupported pull protocol version" {
        StatusCode::BAD_REQUEST
    } else if message == "Pull request expired" {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    }
}

/// Verify a signed v3 pull request envelope against `socket`'s key lookup,
/// peer trust check, and coverage priming gate.
pub fn authenticate_pull_request_v3<S: MeshPullSocket + ?Sized>(
    socket: &S,
    bytes: &[u8],
) -> Result<(DeviceId, PullRequestV3), (StatusCode, String)> {
    let mut lookup_error: Option<String> = None;
    let (peer, request) = verify_pull_request_v3(bytes, socket.now_ms(), |peer| {
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

/// Server-side handler contract for [`PULL_PATH`] (`POST /mesh/v3/pull`).
pub trait PullV3Handler: Clone + Send + Sync + 'static {
    /// Identity used to sign outgoing [`PullPageV3`] envelopes.
    fn identity(&self) -> &DeviceIdentity;

    /// Current Unix timestamp in milliseconds used to check request clock skew.
    fn now_ms(&self) -> i64 {
        unix_ms() as i64
    }

    /// HLC timestamp stamped onto outgoing [`PullPageV3`] envelopes.
    fn response_hlc(&self) -> Hlc {
        Hlc((self.now_ms().max(0) as u64) << 16)
    }

    /// Look up the pinned 33-byte compressed SEC1 public key for `peer`.
    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, String>;

    /// Whether `peer` is trusted to pull from this node (defaults to `true`
    /// once [`Self::lookup_peer_sec1`] returns a key).
    fn is_peer_trusted(&self, _peer: &DeviceId) -> Result<bool, String> {
        Ok(true)
    }

    /// Whether this node's origin coverage index is primed (defaults to `true`).
    fn is_coverage_primed(&self) -> Result<bool, String> {
        Ok(true)
    }

    /// Validate and record the caller's compaction acknowledgment before
    /// building a page. Returning `Ok(Some(reset_page))` short-circuits page
    /// construction with a signed reset response.
    fn admit_pull_ack(
        &self,
        _peer: &DeviceId,
        _request: &PullRequestV3,
    ) -> impl Future<Output = Result<Option<PullPageV3>, String>> + Send {
        async { Ok(None) }
    }

    /// Construct the response [`PullPageV3`] for an authenticated request.
    fn serve_pull_v3(&self, peer: &DeviceId, request: PullRequestV3) -> Result<PullPageV3, String>;
}

/// Mount `POST /mesh/v3/pull` ([`PULL_PATH`]) backed by `handler`.
pub fn v3_pull_router<H: PullV3Handler>(handler: H) -> axum::Router {
    async fn post_pull_v3<H: PullV3Handler>(
        State(handler): State<H>,
        body: axum::body::Bytes,
    ) -> Response {
        let now_ms = handler.now_ms();
        let mut lookup_error: Option<String> = None;
        let (peer, request) =
            match verify_pull_request_v3(&body, now_ms, |id| match handler.lookup_peer_sec1(id) {
                Ok(key) => Ok(key),
                Err(error) => {
                    lookup_error = Some(error.clone());
                    Err(error)
                }
            }) {
                Ok(verified) => verified,
                Err(message) => {
                    if let Some(error) = lookup_error {
                        return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
                    }
                    return (classify_pull_request_error(&message), message).into_response();
                }
            };
        match handler.is_peer_trusted(&peer) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::FORBIDDEN,
                    "Pull requester is not a trusted device",
                )
                    .into_response();
            }
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
        match handler.is_coverage_primed() {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Origin coverage is still priming",
                )
                    .into_response();
            }
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
        let page = match handler.admit_pull_ack(&peer, &request).await {
            Ok(Some(reset)) => reset,
            Ok(None) => match handler.serve_pull_v3(&peer, request) {
                Ok(page) => page,
                Err(message) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
                }
            },
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        };
        match seal_pull_page_v3(&page, handler.identity(), handler.response_hlc()) {
            Ok(bytes) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response(),
            Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
    }

    axum::Router::new()
        .route(PULL_PATH, post(post_pull_v3::<H>))
        .layer(DefaultBodyLimit::max(MAX_V3_REQUEST_BYTES))
        .with_state(handler)
}

impl<L: LogSource, D: DeviceBook> PullV3Handler for ServeState<L, D> {
    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, String> {
        self.relay_callers.try_key_for_device(peer)
    }

    fn admit_pull_ack(
        &self,
        peer: &DeviceId,
        request: &PullRequestV3,
    ) -> impl Future<Output = Result<Option<PullPageV3>, String>> + Send {
        let result = admit_pull_ack_v3(self, peer, request);
        async move { result }
    }

    fn serve_pull_v3(&self, peer: &DeviceId, request: PullRequestV3) -> Result<PullPageV3, String> {
        build_pull_page_v3(self, peer, &request)
    }
}
