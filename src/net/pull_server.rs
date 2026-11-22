//! Pull Protocol v3 server mechanics: two-channel page builder, compaction
//! acknowledgment admission, request authentication, and the Axum router.

use std::future::Future;

use super::pull_budget::{Admission, admit_row, build_keyed_channel};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use super::pull_client::{decode_epoch, unix_ms};
use super::server::ServeState;
use super::socket::MeshPullSocket;
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity, encode_hex};
use crate::log::{LogSource, RelayStreamState};
use crate::pull::{
    CoverageVector, MAX_PULL_REQUEST_BYTES, PULL_PAGE_BYTE_BUDGET, PULL_PAGE_LIMIT_MAX, PULL_PATH,
    PULL_VERSION, PullPage, PullPhase, PullRequest, Resume, seal_pull_page, verify_pull_request,
};
use crate::registry::DeviceBook;

/// Mirrors `relay_needs_reset` so channel B inherits v2's epoch and floor
/// reset semantics verbatim.
pub fn pull_needs_reset(request_epoch: [u8; 32], after: u64, state: &RelayStreamState) -> bool {
    (request_epoch == [0u8; 32] && state.floor > 0)
        || (request_epoch != [0u8; 32] && request_epoch != state.epoch)
        || (request_epoch == state.epoch && (after < state.floor || after > state.head))
}

/// Construct a reset [`PullPage`] advertising `stream`'s current epoch,
/// compaction floor, and head sequence.
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
    let mut budget = limit;
    let mut keyed = Vec::new();
    if !resume_backfill {
        let (served, keyed_resume) = build_keyed_channel(
            socket,
            &claims,
            resume_keyed,
            audit,
            limit,
            PULL_PAGE_BYTE_BUDGET,
            None,
            &own,
        )?;
        keyed = served;
        budget = limit.saturating_sub(keyed.len());
        // The requester acks `next_relay_seq`, and compaction prunes what every
        // peer has acked. So the cursor stays put until the keyed channel has
        // handed over everything the requester's claims do not cover.
        if keyed_resume.is_some() {
            return Ok(page(Vec::new(), keyed, next_relay_seq, keyed_resume));
        }
        if budget == 0 {
            let resume = Some(backfill_resume(start_seq));
            return Ok(page(Vec::new(), keyed, next_relay_seq, resume));
        }
    }

    let mut backfill = Vec::new();
    let mut page_bytes: usize = keyed.iter().map(String::len).sum();
    let mut byte_cut = false;
    let mut scanned_len = 0usize;
    if start_seq < stream.head && page_bytes < PULL_PAGE_BYTE_BUDGET {
        let scanned = socket.relay_since_with_envelopes(start_seq, budget)?;
        scanned_len = scanned.len();
        for (seq, op, envelope) in scanned {
            if byte_cut && claims.covers(&op.order_key()) {
                break;
            }
            if !claims.covers(&op.order_key()) {
                next_relay_seq = seq;
                continue;
            }
            match admit_row(
                |key| socket.is_superseded(key),
                op.order_key(),
                &envelope,
                page_bytes > 0,
                &mut page_bytes,
                PULL_PAGE_BYTE_BUDGET,
            )? {
                Admission::Push(row) => backfill.push((seq, row)),
                Admission::Defer => {
                    byte_cut = true;
                    break;
                }
                Admission::SkipOversized => {}
            }
            next_relay_seq = seq;
            byte_cut = page_bytes >= PULL_PAGE_BYTE_BUDGET;
        }
    }
    let resume = (scanned_len == budget || byte_cut).then(|| backfill_resume(next_relay_seq));
    Ok(page(backfill, keyed, next_relay_seq, resume))
}

/// Validate a presented compaction acknowledgment against `socket`'s current
/// stream state and record it if valid, returning `Ok(Some(reset_page))` when
/// the presented cursor requires a stream reset.
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

/// Map a [`verify_pull_request`] error string to the canonical HTTP status
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

/// Verify a signed pull request envelope against `socket`'s key lookup,
/// peer trust check, and coverage priming gate.
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

/// Server-side handler contract for [`PULL_PATH`] (`POST /mesh/pull`).
pub trait PullHandler: Clone + Send + Sync + 'static {
    /// Identity used to sign outgoing [`PullPage`] envelopes.
    fn identity(&self) -> &DeviceIdentity;

    /// Current Unix timestamp in milliseconds used to check request clock skew.
    fn now_ms(&self) -> i64 {
        unix_ms() as i64
    }

    /// HLC timestamp stamped onto outgoing [`PullPage`] envelopes.
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
        _request: &PullRequest,
    ) -> impl Future<Output = Result<Option<PullPage>, String>> + Send {
        async { Ok(None) }
    }

    /// Construct the response [`PullPage`] for an authenticated request.
    fn serve_pull(&self, peer: &DeviceId, request: PullRequest) -> Result<PullPage, String>;
}

/// Mount `POST /mesh/pull` ([`PULL_PATH`]) backed by `handler`.
pub fn pull_router<H: PullHandler>(handler: H) -> axum::Router {
    async fn post_pull<H: PullHandler>(
        State(handler): State<H>,
        body: axum::body::Bytes,
    ) -> Response {
        let now_ms = handler.now_ms();
        let mut lookup_error: Option<String> = None;
        let (peer, request) =
            match verify_pull_request(&body, now_ms, |id| match handler.lookup_peer_sec1(id) {
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
            Ok(None) => match handler.serve_pull(&peer, request) {
                Ok(page) => page,
                Err(message) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
                }
            },
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        };
        match seal_pull_page(&page, handler.identity(), handler.response_hlc()) {
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
        .route(PULL_PATH, post(post_pull::<H>))
        .layer(DefaultBodyLimit::max(MAX_PULL_REQUEST_BYTES))
        .with_state(handler)
}

impl<L: LogSource, D: DeviceBook> PullHandler for ServeState<L, D> {
    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, String> {
        self.relay_callers.try_key_for_device(peer)
    }

    fn admit_pull_ack(
        &self,
        peer: &DeviceId,
        request: &PullRequest,
    ) -> impl Future<Output = Result<Option<PullPage>, String>> + Send {
        let result = admit_pull_ack(self, peer, request);
        async move { result }
    }

    fn serve_pull(&self, peer: &DeviceId, request: PullRequest) -> Result<PullPage, String> {
        build_pull_page(self, peer, &request)
    }
}
