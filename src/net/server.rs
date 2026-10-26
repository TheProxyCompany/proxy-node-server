//! Axum serving state and HTTP handlers for v1 semantic pull, Relay v2, and
//! `/devices`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use tokio::sync::Semaphore;

use super::relay::{
    DEVICE_BOOK_NONCE_HEADER, DEVICE_BOOK_SIGNATURE_HEADER, RELAY_HEAD_REQUEST_CONTEXT,
    RELAY_HEAD_SIGNING_CONTEXT, RELAY_OPS_REQUEST_CONTEXT, RELAY_OPS_SIGNING_CONTEXT,
    RELAY_WATCH_REQUEST_CONTEXT, RELAY_WATCH_SIGNING_CONTEXT, RelayReplayCache, relay_needs_reset,
    relay_request, sign_device_book, signed_relay_response, valid_relay_state,
};
use super::watch::HeadWatch;
use super::{
    DEFAULT_MAX_PARKED_WATCHES, DEFAULT_PULL_LIMIT, DeviceEntry, DevicesResp, IdentityResp,
    PullResponse, WATCH_DEFAULT_WAIT, WATCH_MAX_WAIT, decode_fixed_hex, decode_order_key,
};
use crate::identity::{DeviceIdentity, encode_hex};
use crate::log::LogSource;
use crate::op::OrderKey;
use crate::registry::DeviceBook;

/// Shared state the pull routes serve from: this node's identity, its op-log
/// ([`LogSource`]), the device keys it gossips ([`DeviceBook`]), and the
/// head-change notifier `/watch` parks on.
pub struct ServeState<L: LogSource, D: DeviceBook> {
    identity: Arc<DeviceIdentity>,
    log: L,
    devices: D,
    relay_callers: D,
    watch: HeadWatch,
    watch_limit: Arc<Semaphore>,
    pub(super) relay_replays: Arc<RelayReplayCache>,
}

impl<L: LogSource, D: DeviceBook> Clone for ServeState<L, D> {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            log: self.log.clone(),
            devices: self.devices.clone(),
            relay_callers: self.relay_callers.clone(),
            watch: self.watch.clone(),
            watch_limit: self.watch_limit.clone(),
            relay_replays: self.relay_replays.clone(),
        }
    }
}

impl<L: LogSource, D: DeviceBook> ServeState<L, D> {
    pub fn new(identity: Arc<DeviceIdentity>, log: L, devices: D) -> Self {
        Self {
            identity,
            log,
            relay_callers: devices.clone(),
            devices,
            watch: HeadWatch::inert(),
            watch_limit: Arc::new(Semaphore::new(DEFAULT_MAX_PARKED_WATCHES)),
            relay_replays: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_watch(mut self, watch: HeadWatch) -> Self {
        self.watch = watch;
        self
    }

    pub fn with_relay_callers(mut self, relay_callers: D) -> Self {
        self.relay_callers = relay_callers;
        self
    }

    pub fn with_watch_limit(mut self, max: usize) -> Self {
        self.watch_limit = Arc::new(Semaphore::new(max));
        self
    }
}

/// Build the v1 semantic-order routes, the insertion-ordered authenticated v2
/// relay routes, and `/devices`.
pub fn router<L: LogSource, D: DeviceBook>(state: ServeState<L, D>) -> Router {
    Router::new()
        .route("/identity", get(get_identity::<L, D>))
        .route("/ops", get(get_ops::<L, D>))
        .route("/head", get(get_head::<L, D>))
        .route("/watch", get(get_watch::<L, D>))
        .route("/v2/ops", get(get_relay_ops_v2::<L, D>))
        .route("/v2/head", get(get_relay_head_v2::<L, D>))
        .route("/v2/watch", get(get_relay_watch_v2::<L, D>))
        .route("/devices", get(get_devices::<L, D>))
        .with_state(state)
}

/// Build the authenticated relay-v2 production routes without exposing the
/// legacy unauthenticated semantic-log endpoints.
pub fn relay_router<L: LogSource, D: DeviceBook>(state: ServeState<L, D>) -> Router {
    Router::new()
        .route("/identity", get(get_identity::<L, D>))
        .route("/v2/ops", get(get_relay_ops_v2::<L, D>))
        .route("/v2/head", get(get_relay_head_v2::<L, D>))
        .route("/v2/watch", get(get_relay_watch_v2::<L, D>))
        .route("/devices", get(get_devices::<L, D>))
        .with_state(state)
}

pub(super) fn octet(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

async fn get_identity<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
) -> Response {
    let resp = IdentityResp {
        device_id: *state.identity.device_id().as_bytes(),
        public_key_sec1: state.identity.public_key_sec1().to_vec(),
    };
    match postcard::to_allocvec(&resp) {
        Ok(bytes) => octet(bytes),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct OpsQuery {
    since: Option<String>,
    limit: Option<u16>,
}

async fn get_ops<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
    Query(q): Query<OpsQuery>,
) -> Response {
    let cursor = match q.since.as_deref() {
        Some(s) if !s.is_empty() => match decode_order_key(s) {
            Some(key) => key,
            None => return StatusCode::BAD_REQUEST.into_response(),
        },
        _ => OrderKey::MIN,
    };
    let limit = q.limit.unwrap_or(DEFAULT_PULL_LIMIT) as usize;

    let mut ops = Vec::new();
    let mut next = cursor;
    for op in state.log.since(cursor, limit) {
        match op.to_bytes() {
            Ok(bytes) => {
                ops.push(bytes);
                next = op.order_key();
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    let resp = PullResponse {
        ops,
        next: next.to_wire().to_vec(),
    };
    match postcard::to_allocvec(&resp) {
        Ok(bytes) => octet(bytes),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_head<L: LogSource, D: DeviceBook>(State(state): State<ServeState<L, D>>) -> Response {
    let head = state.log.head().unwrap_or(OrderKey::MIN);
    octet(head.to_wire().to_vec())
}

#[derive(Deserialize)]
struct WatchQuery {
    head: Option<String>,
    wait: Option<u64>,
}

async fn get_watch<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
    Query(q): Query<WatchQuery>,
) -> Response {
    let known = match q.head.as_deref() {
        Some(s) if !s.is_empty() => match decode_order_key(s) {
            Some(key) => key,
            None => return StatusCode::BAD_REQUEST.into_response(),
        },
        _ => OrderKey::MIN,
    };
    let wait = q
        .wait
        .map(Duration::from_millis)
        .unwrap_or(WATCH_DEFAULT_WAIT)
        .min(WATCH_MAX_WAIT);
    let head = match state.watch_limit.clone().try_acquire_owned() {
        Ok(_permit) => {
            state
                .watch
                .clone()
                .until_head_changes(&state.log, known, wait)
                .await
        }
        Err(_) => state.log.head().unwrap_or(OrderKey::MIN),
    };
    octet(head.to_wire().to_vec())
}

#[derive(Deserialize)]
struct RelayBaseQueryV2 {
    epoch: String,
    after: u64,
}

#[derive(Deserialize)]
struct RelayOpsQueryV2 {
    epoch: String,
    after: u64,
    limit: u16,
}

#[derive(Deserialize)]
struct RelayWatchQueryV2 {
    epoch: String,
    after: u64,
    wait: u64,
}

async fn get_relay_ops_v2<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
    Query(query): Query<RelayOpsQueryV2>,
    headers: HeaderMap,
) -> Response {
    if query.limit == 0 || query.limit > DEFAULT_PULL_LIMIT {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let request = match relay_request(
        &query.epoch,
        query.after,
        query.limit as u64,
        &headers,
        RELAY_OPS_REQUEST_CONTEXT,
        state.identity.device_id(),
        &state.relay_callers,
        &state.relay_replays,
    ) {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };
    let request_epoch = request.epoch;
    let nonce = request.nonce;
    let stream = match state.log.relay_state() {
        Ok(Some(stream)) => stream,
        Ok(None) => return StatusCode::NOT_IMPLEMENTED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if !valid_relay_state(stream) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if relay_needs_reset(request_epoch, query.after, stream) {
        return signed_relay_response(
            &state.identity,
            request.caller,
            RELAY_OPS_SIGNING_CONTEXT,
            request_epoch,
            query.after,
            query.limit as u64,
            nonce,
            stream,
            true,
            stream.floor,
            Vec::new(),
        );
    }
    let page = match state.log.relay_page(query.after, query.limit as usize) {
        Ok(Some(page)) => page,
        Ok(None) => return StatusCode::NOT_IMPLEMENTED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if !valid_relay_state(page.state) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if relay_needs_reset(request_epoch, query.after, page.state) {
        return signed_relay_response(
            &state.identity,
            request.caller,
            RELAY_OPS_SIGNING_CONTEXT,
            request_epoch,
            query.after,
            query.limit as u64,
            nonce,
            page.state,
            true,
            page.state.floor,
            Vec::new(),
        );
    }
    if page.entries.len() > query.limit as usize {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut previous = query.after;
    for entry in &page.entries {
        if previous.checked_add(1) != Some(entry.seq) || entry.seq > page.state.head {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        previous = entry.seq;
    }
    let next = page
        .entries
        .last()
        .map(|entry| entry.seq)
        .unwrap_or(query.after);
    signed_relay_response(
        &state.identity,
        request.caller,
        RELAY_OPS_SIGNING_CONTEXT,
        request_epoch,
        query.after,
        query.limit as u64,
        nonce,
        page.state,
        false,
        next,
        page.entries,
    )
}

async fn get_relay_head_v2<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
    Query(query): Query<RelayBaseQueryV2>,
    headers: HeaderMap,
) -> Response {
    let request = match relay_request(
        &query.epoch,
        query.after,
        0,
        &headers,
        RELAY_HEAD_REQUEST_CONTEXT,
        state.identity.device_id(),
        &state.relay_callers,
        &state.relay_replays,
    ) {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };
    let request_epoch = request.epoch;
    let nonce = request.nonce;
    let stream = match state.log.relay_state() {
        Ok(Some(stream)) => stream,
        Ok(None) => return StatusCode::NOT_IMPLEMENTED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if !valid_relay_state(stream) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let reset = relay_needs_reset(request_epoch, query.after, stream);
    signed_relay_response(
        &state.identity,
        request.caller,
        RELAY_HEAD_SIGNING_CONTEXT,
        request_epoch,
        query.after,
        0,
        nonce,
        stream,
        reset,
        if reset { stream.floor } else { query.after },
        Vec::new(),
    )
}

async fn get_relay_watch_v2<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
    Query(query): Query<RelayWatchQueryV2>,
    headers: HeaderMap,
) -> Response {
    let request = match relay_request(
        &query.epoch,
        query.after,
        query.wait,
        &headers,
        RELAY_WATCH_REQUEST_CONTEXT,
        state.identity.device_id(),
        &state.relay_callers,
        &state.relay_replays,
    ) {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };
    let request_epoch = request.epoch;
    let nonce = request.nonce;
    let initial = match state.log.relay_state() {
        Ok(Some(stream)) => stream,
        Ok(None) => return StatusCode::NOT_IMPLEMENTED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if !valid_relay_state(initial) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let initial_reset = relay_needs_reset(request_epoch, query.after, initial);
    let stream = if initial_reset
        || request_epoch == [0u8; 32]
        || initial.head > query.after
        || initial.head < query.after
    {
        initial
    } else {
        let wait = Duration::from_millis(query.wait).min(WATCH_MAX_WAIT);
        match state.watch_limit.clone().try_acquire_owned() {
            Ok(_permit) => match state
                .watch
                .clone()
                .until_relay_changes(&state.log, request_epoch, query.after, wait)
                .await
            {
                Ok(Some(stream)) => stream,
                Ok(None) => return StatusCode::NOT_IMPLEMENTED.into_response(),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            },
            Err(_) => initial,
        }
    };
    if !valid_relay_state(stream) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let reset = relay_needs_reset(request_epoch, query.after, stream);
    signed_relay_response(
        &state.identity,
        request.caller,
        RELAY_WATCH_SIGNING_CONTEXT,
        request_epoch,
        query.after,
        query.wait,
        nonce,
        stream,
        reset,
        if reset { stream.floor } else { query.after },
        Vec::new(),
    )
}

async fn get_devices<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
    headers: HeaderMap,
) -> Response {
    let nonce = match headers.get(DEVICE_BOOK_NONCE_HEADER) {
        Some(value) => {
            let Ok(encoded) = value.to_str() else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(nonce) = decode_fixed_hex::<32>(encoded) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            Some(nonce)
        }
        None => None,
    };
    let devices = match state.devices.try_known_devices() {
        Ok(devices) => devices,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    .into_iter()
    .map(|(id, sec1)| DeviceEntry {
        device_id: *id.as_bytes(),
        public_key_sec1: sec1.to_vec(),
    })
    .collect();
    let resp = DevicesResp { devices };
    match postcard::to_allocvec(&resp) {
        Ok(bytes) => {
            let signature = if let Some(nonce) = nonce {
                let signature = sign_device_book(&state.identity, &nonce, &bytes);
                let Ok(header) = HeaderValue::from_str(&encode_hex(&signature)) else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                Some(header)
            } else {
                None
            };
            let mut response = octet(bytes);
            if let Some(signature) = signature {
                response.headers_mut().insert(
                    HeaderName::from_static(DEVICE_BOOK_SIGNATURE_HEADER),
                    signature,
                );
            }
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
