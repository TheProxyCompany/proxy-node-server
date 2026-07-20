//! HTTP pull transport (feature `pull-http`): the server routes a node exposes,
//! the [`HttpPullSource`] client that pulls a peer's ops, and [`sync_once`], the
//! one-shot pull step the daemon loops over. All bodies are postcard over
//! `application/octet-stream`.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use p256::ecdsa::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, watch};

use crate::durable::OplogWriter;
use crate::error::TransportError;
use crate::hlc::NodeClock;
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::{LogSource, OpLog, RelayLogEntry, RelayStreamState, apply_range, replay};
use crate::op::{OrderKey, SignedOp};
use crate::registry::{DeviceBook, DeviceRegistry};
use crate::store::Store;
use crate::transport::{Cursor, PullSource};

/// Default cap on the number of ops returned by one `/ops` page.
pub const DEFAULT_PULL_LIMIT: u16 = 512;

/// Default per-request timeout for a pull/probe. Bounds a single request so one
/// blackholed peer (e.g. a stale tailnet IP) can never hang a browse tick or a
/// pull loop indefinitely; `reqwest::Client` has no timeout by default.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Default server-hold for a `/watch` long-poll: how long a parked handler waits
/// for the head to move before returning the unchanged head. The client re-arms
/// on return, so this is the idle re-poll cadence, not a latency floor.
pub const WATCH_DEFAULT_WAIT: Duration = Duration::from_millis(25_000);

/// Client-side backoff after a `/watch` that returns `Ok` but *no new data* —
/// a returned head at or behind the caller's cursor. Two cases produce this: a
/// clean hold-window close with no append, and — the one this guards — an
/// over-capacity server that sheds the park and answers immediately with the
/// current head (see [`ServeState::with_watch_limit`]). A consumer that treats
/// any `Ok` as a pull trigger re-arms instantly on such a reply, spinning a
/// tight watch/empty-pull loop under saturation. Sleeping this delay before
/// re-arming collapses the loop; a genuine head move (head strictly past the
/// cursor) returns with no backoff, so this only ever bounds *idle* re-arm
/// latency, never the delivery of real ops. 500ms caps a saturated link at two
/// re-arms per second — negligible against the multi-second hold window.
pub const WATCH_EMPTY_BACKOFF: Duration = Duration::from_millis(500);

/// Hard cap on the `/watch` hold. Kept under proxy idle limits (nginx 60s,
/// Cloudflare 100s) so the *server* always closes the long-poll cleanly and no
/// intermediary tears it down mid-flight.
pub const WATCH_MAX_WAIT: Duration = Duration::from_millis(50_000);

/// Default cap on concurrently *parked* `/watch` long-polls. Each parked handler
/// holds a connection and a task for up to [`WATCH_MAX_WAIT`], so once the route
/// is proxy-exposed an unbounded park count is a DoS surface. At the cap `/watch`
/// degrades to an immediate head response (the caller falls back to polling) —
/// admission control that sheds load instead of accumulating parked tasks.
/// Overridable per-node via [`ServeState::with_watch_limit`].
pub const DEFAULT_MAX_PARKED_WATCHES: usize = 64;

/// Version carried inside every relay-local v2 response body.
pub const RELAY_PROTOCOL_VERSION: u8 = 2;

const RELAY_OPS_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/relay/ops/v2\0";
const RELAY_HEAD_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/relay/head/v2\0";
const RELAY_WATCH_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/relay/watch/v2\0";
const RELAY_OPS_REQUEST_CONTEXT: &[u8] = b"proxy-node-server/relay/request/ops/v2\0";
const RELAY_HEAD_REQUEST_CONTEXT: &[u8] = b"proxy-node-server/relay/request/head/v2\0";
const RELAY_WATCH_REQUEST_CONTEXT: &[u8] = b"proxy-node-server/relay/request/watch/v2\0";
const RELAY_NONCE_HEADER: &str = "x-proxy-relay-nonce";
const RELAY_CALLER_HEADER: &str = "x-proxy-relay-caller";
const RELAY_REQUEST_SIGNATURE_HEADER: &str = "x-proxy-relay-request-signature";
const RELAY_SIGNATURE_HEADER: &str = "x-proxy-relay-signature";

const RELAY_REPLAY_TTL: Duration = Duration::from_secs(5 * 60);
const RELAY_REPLAY_LIMIT: usize = 4096;
type RelayReplayCache = Mutex<HashMap<(DeviceId, [u8; 32]), Instant>>;

/// Domain separation for the serving peer's signature over a fresh challenge
/// and its exact postcard-encoded [`DevicesResp`] body. The serving [`DeviceId`]
/// is included so the attestation is also bound to the already-pinned peer.
const DEVICE_BOOK_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/device-book/v2\0";

/// Hex-encoded 32-byte challenge generated afresh by an attested caller.
const DEVICE_BOOK_NONCE_HEADER: &str = "x-proxy-device-book-nonce";

/// Hex-encoded, fixed-width P-256 signature over the request challenge and the
/// exact `/devices` response body. The body remains the legacy [`DevicesResp`]
/// postcard payload so existing callers can continue to consume it as
/// untrusted gossip.
const DEVICE_BOOK_SIGNATURE_HEADER: &str = "x-proxy-device-book-signature";

/// `/identity` response: what a puller needs to verify this peer's ops. The key
/// is a `Vec<u8>` (33-byte compressed SEC1) because serde derives (de)serialize
/// for byte arrays only up to length 32; the length is validated on decode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResp {
    pub device_id: [u8; 32],
    pub public_key_sec1: Vec<u8>,
}

/// `/ops` response: a page of envelope bytes plus the resume cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullResponse {
    /// Each entry is one [`SignedOp::to_bytes`] envelope, in total order.
    pub ops: Vec<Vec<u8>>,
    /// Highest order key returned (72-byte [`OrderKey`] wire form), or the echoed
    /// `since` when the page is empty. `Vec<u8>` for the same serde-array reason.
    pub next: Vec<u8>,
}

/// Resume point for the insertion-ordered relay-local v2 stream. The all-zero
/// epoch is the explicit first-contact sentinel; a successful response replaces
/// it with the server's authenticated stream epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayCursorV2 {
    pub epoch: [u8; 32],
    pub after: u64,
}

impl RelayCursorV2 {
    pub const START: Self = Self {
        epoch: [0; 32],
        after: 0,
    };
}

impl Default for RelayCursorV2 {
    fn default() -> Self {
        Self::START
    }
}

/// Wire entry authenticated inside a [`RelayResponseV2`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayWireEntryV2 {
    pub seq: u64,
    pub envelope: Vec<u8>,
}

/// Exact postcard body returned by all three relay-local v2 routes. `/v2/head`
/// and `/v2/watch` carry no entries; `/v2/ops` carries a bounded page.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayResponseV2 {
    pub v: u8,
    pub epoch: [u8; 32],
    pub head: u64,
    pub floor: u64,
    /// Last sequence actually carried by an ops page, or the request's `after`
    /// for a head/watch response. A reset instead returns `floor`.
    pub next: u64,
    pub reset: bool,
    pub entries: Vec<RelayWireEntryV2>,
}

/// One verified and decoded operation from a relay-local page.
#[derive(Clone, Debug)]
pub struct RelayOpV2 {
    pub seq: u64,
    pub op: SignedOp,
}

/// Authenticated, validated, and envelope-decoded v2 response returned to
/// callers. `reset` instructs the caller to replace its cursor with
/// [`RelayPageV2::cursor`] before requesting again.
#[derive(Clone, Debug)]
pub struct RelayPageV2 {
    pub epoch: [u8; 32],
    pub head: u64,
    pub floor: u64,
    pub next: u64,
    pub reset: bool,
    pub entries: Vec<RelayOpV2>,
}

impl RelayPageV2 {
    /// Safe continuation cursor. Head/watch responses preserve the caller's
    /// `after`, so observing available work never skips entries not yet pulled.
    pub fn cursor(&self) -> RelayCursorV2 {
        RelayCursorV2 {
            epoch: self.epoch,
            after: self.next,
        }
    }
}

/// One `(device_id, verifying key)` pair the node knows and trusts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: [u8; 32],
    /// 33-byte compressed SEC1 key; `Vec<u8>` for the same serde-array reason
    /// as [`IdentityResp`]. The length is validated on learn.
    pub public_key_sec1: Vec<u8>,
}

/// `/devices` response: every device this node will vouch for, so a puller can
/// verify transitively-relayed ops from devices it never met directly (D11).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevicesResp {
    pub devices: Vec<DeviceEntry>,
}

// ---------------------------------------------------------------------------
// Push wake-up (`/watch`): a head-change notifier that turns the sleep between
// pull rounds into a blocking wait resolving the instant the peer's head moves.
// It is a *wake-up signal only* — it transfers no ops and touches none of the
// pull invariants; the authoritative path stays the verify-before-advance pull.
// ---------------------------------------------------------------------------

/// Publisher side of the push wake-up, fed the new head from every op-append
/// path (local emit + remote pull-apply). Backed by a `tokio::sync::watch` used
/// as a pure tick: its value is advisory (debug only) — `/watch` correctness
/// reads the authoritative [`LogSource::head`], never the channel value. One
/// sender wakes every parked handler, so fanout needs no per-connection
/// registry, and a burst of appends coalesces into a single wake (the watch
/// keeps only the newest value), which drives exactly one pull batch, not N.
pub struct HeadPublisher {
    tx: watch::Sender<(u64, OrderKey)>,
}

impl HeadPublisher {
    pub fn new(initial: OrderKey) -> Self {
        let (tx, _rx) = watch::channel((0, initial));
        Self { tx }
    }

    /// A reader parked handlers block on. Cloneable through [`ServeState`].
    pub fn watch(&self) -> HeadWatch {
        HeadWatch {
            rx: Some(self.tx.subscribe()),
        }
    }

    /// Signal one newly inserted operation. Every call advances an internal
    /// arrival tick even when the semantic `OrderKey` head is unchanged, so v2
    /// watchers wake for a late lower-order op. V1 watchers re-read their
    /// semantic head and remain parked when that head did not advance.
    pub fn publish(&self, head: OrderKey) {
        self.tx.send_modify(|current| {
            current.0 = current.0.wrapping_add(1);
            current.1 = head;
        });
    }
}

/// Reader side of the push wake-up, held in [`ServeState`]. [`HeadWatch::inert`]
/// is a watch with no publisher wired: `/watch` then degrades to a bounded
/// long-poll that only ever times out — correct, just no speedup — which is what
/// any [`LogSource`] gets for free before its emit path publishes.
#[derive(Clone)]
pub struct HeadWatch {
    rx: Option<watch::Receiver<(u64, OrderKey)>>,
}

impl HeadWatch {
    pub fn inert() -> Self {
        Self { rx: None }
    }

    /// Block until `log.head() > known` (the peer has ops the caller has not
    /// pulled) or `wait` elapses, then return the head to report. The comparison
    /// is *directional*: only a strictly-newer head returns early. A caller whose
    /// cursor sorts at or ahead of this peer's head (`known >= head` — e.g. a
    /// cursor that has already crossed this peer's ops, or one carrying a forged
    /// far-future key) parks out the whole window instead of returning
    /// immediately, so it can never drive a tight watch/empty-pull loop.
    ///
    /// Ordering is the correctness crux: [`watch::Receiver::borrow_and_update`]
    /// marks the current version seen *before* the head is read, so an append
    /// landing between the mark and the read is caught by the read (return now),
    /// and an append landing between the read and the park bumps the version
    /// after our mark, so [`watch::Receiver::changed`] is already ready → loop →
    /// re-read → return. No wake is ever lost.
    pub async fn until_head_changes<L: LogSource>(
        mut self,
        log: &L,
        known: OrderKey,
        wait: Duration,
    ) -> OrderKey {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(rx) = self.rx.as_mut() {
                rx.borrow_and_update();
            }
            let cur = log.head().unwrap_or(OrderKey::MIN);
            if cur > known {
                return cur;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return cur;
            }
            match self.rx.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        changed = rx.changed() => {
                            if changed.is_err() {
                                // Every publisher dropped: no further wake can
                                // arrive. Hold out the remaining window like the
                                // inert path so a dropped publisher can never
                                // busy-spin the handler or the client.
                                tokio::time::sleep(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await;
                                return log.head().unwrap_or(OrderKey::MIN);
                            }
                            // Version bumped: loop to re-read the head.
                        }
                        _ = tokio::time::sleep(remaining) => {
                            return log.head().unwrap_or(OrderKey::MIN);
                        }
                    }
                }
                None => {
                    tokio::time::sleep(remaining).await;
                    return log.head().unwrap_or(OrderKey::MIN);
                }
            }
        }
    }

    /// Block until the relay-local stream changes relative to `(epoch, after)`
    /// or `wait` elapses. Unlike the v1 semantic-head comparison, this observes
    /// every unique insertion through [`RelayStreamState::head`].
    pub async fn until_relay_changes<L: LogSource>(
        mut self,
        log: &L,
        epoch: [u8; 32],
        after: u64,
        wait: Duration,
    ) -> Result<Option<RelayStreamState>, String> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(rx) = self.rx.as_mut() {
                rx.borrow_and_update();
            }
            let Some(state) = log.relay_state()? else {
                return Ok(None);
            };
            if state.epoch != epoch
                || after < state.floor
                || after > state.head
                || state.head > after
            {
                return Ok(Some(state));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(Some(state));
            }
            match self.rx.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        changed = rx.changed() => {
                            if changed.is_err() {
                                tokio::time::sleep(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await;
                                return log.relay_state();
                            }
                        }
                        _ = tokio::time::sleep(remaining) => {
                            return log.relay_state();
                        }
                    }
                }
                None => {
                    tokio::time::sleep(remaining).await;
                    return log.relay_state();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Shared state the pull routes serve from: this node's identity, its op-log
/// ([`LogSource`]), the device keys it gossips ([`DeviceBook`]), and the
/// head-change notifier `/watch` parks on. Both logs are generic so the
/// reference in-memory log/registry and Grand Central's proxy.db-backed
/// log/devices table mount the same routes.
pub struct ServeState<L: LogSource, D: DeviceBook> {
    identity: Arc<DeviceIdentity>,
    log: L,
    devices: D,
    relay_callers: D,
    watch: HeadWatch,
    /// Admission control for `/watch`: caps the number of handlers parked at once
    /// so the route cannot be turned into a park-and-hold DoS. Shared across the
    /// [`Clone`]d per-connection states, so the cap is process-wide per node.
    watch_limit: Arc<Semaphore>,
    relay_replays: Arc<RelayReplayCache>,
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
    /// Build serve state with an inert watch, so every existing caller compiles
    /// unchanged and its `/watch` is a bounded long-poll until a publisher is
    /// wired via [`ServeState::with_watch`]. The parked-watch cap defaults to
    /// [`DEFAULT_MAX_PARKED_WATCHES`]; override with [`ServeState::with_watch_limit`].
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

    /// Opt into push delivery: park `/watch` handlers on `watch`, which a
    /// [`HeadPublisher`] on the node's append path wakes on every head change.
    pub fn with_watch(mut self, watch: HeadWatch) -> Self {
        self.watch = watch;
        self
    }

    /// Use a narrower key book for live relay callers than for historical op
    /// verification and `/devices` gossip. The reference daemon uses this to
    /// keep peer-vouched signer keys from becoming direct read principals.
    pub fn with_relay_callers(mut self, relay_callers: D) -> Self {
        self.relay_callers = relay_callers;
        self
    }

    /// Override the concurrent-parked-`/watch` cap (default
    /// [`DEFAULT_MAX_PARKED_WATCHES`]). Beyond `max` in-flight parks, `/watch`
    /// answers immediately with the current head so callers degrade to polling.
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
/// legacy unauthenticated semantic-log endpoints. `/identity` remains the
/// bootstrap key-discovery seam; relay requests prove possession thereafter.
pub fn relay_router<L: LogSource, D: DeviceBook>(state: ServeState<L, D>) -> Router {
    Router::new()
        .route("/identity", get(get_identity::<L, D>))
        .route("/v2/ops", get(get_relay_ops_v2::<L, D>))
        .route("/v2/head", get(get_relay_head_v2::<L, D>))
        .route("/v2/watch", get(get_relay_watch_v2::<L, D>))
        .route("/devices", get(get_devices::<L, D>))
        .with_state(state)
}

fn octet(bytes: Vec<u8>) -> Response {
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

/// `/watch` — `/head` with a blocking condition. Returns immediately when our
/// head is *strictly newer* than the caller's `head` (the primary herd guard: a
/// caller mid-pagination or already behind never parks), else parks until the
/// head advances past the caller's or `wait` (clamped to [`WATCH_MAX_WAIT`])
/// elapses. The response is the identical 72-byte [`OrderKey`] wire form `/head`
/// returns. The caller passes its pull cursor as `head`, and cursor and peer-head
/// share the `OrderKey` space, so "head > cursor" is exactly "peer has ops I have
/// not pulled" — valid even across pagination. The comparison is directional on
/// purpose: a cursor that sorts at or ahead of our head never short-circuits, so
/// it cannot spin a tight watch/empty-pull loop (see [`HeadWatch::until_head_changes`]).
///
/// Parks are admission-controlled: at [`ServeState::with_watch_limit`] concurrent
/// parked handlers the route stops parking and answers immediately with the
/// current head, shedding load to polling instead of accumulating parked tasks.
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
    // Take an admission permit for the whole park. At capacity, skip parking and
    // return the current head so the caller polls — the DoS guard for a
    // proxy-exposed `/watch`. The permit is released when the handler returns.
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

#[derive(Clone, Copy)]
struct RelayRequestAuth {
    epoch: [u8; 32],
    nonce: [u8; 32],
    caller: DeviceId,
}

#[allow(clippy::too_many_arguments)]
fn relay_request<D: DeviceBook>(
    epoch: &str,
    after: u64,
    request_bound: u64,
    headers: &HeaderMap,
    request_context: &[u8],
    serving_peer: DeviceId,
    devices: &D,
    replays: &RelayReplayCache,
) -> Result<RelayRequestAuth, StatusCode> {
    let epoch = decode_fixed_hex::<32>(epoch).ok_or(StatusCode::BAD_REQUEST)?;
    if epoch == [0u8; 32] && after != 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let nonce = headers
        .get(RELAY_NONCE_HEADER)
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .ok()
        .and_then(decode_fixed_hex::<32>)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let caller = headers
        .get(RELAY_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(decode_fixed_hex::<32>)
        .map(DeviceId::from_bytes)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let signature = headers
        .get(RELAY_REQUEST_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(decode_fixed_hex::<64>)
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if signature.normalize_s().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let sec1 = devices
        .try_key_for_device(&caller)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if DeviceIdentity::device_id_from_sec1(&sec1).ok() != Some(caller) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let verifying = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| StatusCode::UNAUTHORIZED)?;
    DeviceIdentity::verify(
        &verifying,
        &relay_request_signing_input(
            request_context,
            &caller,
            &serving_peer,
            &epoch,
            after,
            request_bound,
            &nonce,
        ),
        &signature,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let now = Instant::now();
    let mut replays = replays.lock().expect("relay replay cache mutex poisoned");
    replays.retain(|_, seen| now.saturating_duration_since(*seen) <= RELAY_REPLAY_TTL);
    if replays.contains_key(&(caller, nonce)) {
        return Err(StatusCode::CONFLICT);
    }
    if replays.len() >= RELAY_REPLAY_LIMIT {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    replays.insert((caller, nonce), now);
    Ok(RelayRequestAuth {
        epoch,
        nonce,
        caller,
    })
}

fn relay_needs_reset(request_epoch: [u8; 32], after: u64, state: RelayStreamState) -> bool {
    (request_epoch == [0u8; 32] && state.floor > 0)
        || (request_epoch != [0u8; 32] && request_epoch != state.epoch)
        || (request_epoch == state.epoch && (after < state.floor || after > state.head))
}

fn valid_relay_state(state: RelayStreamState) -> bool {
    state.epoch != [0u8; 32] && state.floor <= state.head
}

fn relay_request_signing_input(
    context: &[u8],
    caller: &DeviceId,
    serving_peer: &DeviceId,
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        context.len()
            + caller.as_bytes().len()
            + serving_peer.as_bytes().len()
            + request_epoch.len()
            + 8
            + 8
            + nonce.len(),
    );
    input.extend_from_slice(context);
    input.extend_from_slice(caller.as_bytes());
    input.extend_from_slice(serving_peer.as_bytes());
    input.extend_from_slice(request_epoch);
    input.extend_from_slice(&after.to_be_bytes());
    input.extend_from_slice(&request_bound.to_be_bytes());
    input.extend_from_slice(nonce);
    input
}

#[allow(clippy::too_many_arguments)]
fn sign_relay_request(
    identity: &DeviceIdentity,
    context: &[u8],
    serving_peer: &DeviceId,
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
) -> [u8; 64] {
    let signature = identity.sign(&relay_request_signing_input(
        context,
        &identity.device_id(),
        serving_peer,
        request_epoch,
        after,
        request_bound,
        nonce,
    ));
    let signature = signature.normalize_s().unwrap_or(signature).to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&signature);
    out
}

#[allow(clippy::too_many_arguments)]
fn relay_response_signing_input(
    context: &[u8],
    signer: &DeviceId,
    caller: &DeviceId,
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        context.len()
            + signer.as_bytes().len()
            + caller.as_bytes().len()
            + request_epoch.len()
            + 8
            + 8
            + nonce.len()
            + body.len(),
    );
    input.extend_from_slice(context);
    input.extend_from_slice(signer.as_bytes());
    input.extend_from_slice(caller.as_bytes());
    input.extend_from_slice(request_epoch);
    input.extend_from_slice(&after.to_be_bytes());
    input.extend_from_slice(&request_bound.to_be_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(body);
    input
}

#[allow(clippy::too_many_arguments)]
fn sign_relay_response(
    identity: &DeviceIdentity,
    caller: &DeviceId,
    context: &[u8],
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
    body: &[u8],
) -> [u8; 64] {
    let signature = identity.sign(&relay_response_signing_input(
        context,
        &identity.device_id(),
        caller,
        request_epoch,
        after,
        request_bound,
        nonce,
        body,
    ));
    let signature = signature.normalize_s().unwrap_or(signature).to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&signature);
    out
}

#[allow(clippy::too_many_arguments)]
fn signed_relay_response(
    identity: &DeviceIdentity,
    caller: DeviceId,
    context: &[u8],
    request_epoch: [u8; 32],
    after: u64,
    request_bound: u64,
    nonce: [u8; 32],
    state: RelayStreamState,
    reset: bool,
    next: u64,
    entries: Vec<RelayLogEntry>,
) -> Response {
    let mut wire_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let envelope = match entry.op.to_bytes() {
            Ok(envelope) => envelope,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        wire_entries.push(RelayWireEntryV2 {
            seq: entry.seq,
            envelope,
        });
    }
    let response = RelayResponseV2 {
        v: RELAY_PROTOCOL_VERSION,
        epoch: state.epoch,
        head: state.head,
        floor: state.floor,
        next,
        reset,
        entries: wire_entries,
    };
    let body = match postcard::to_allocvec(&response) {
        Ok(body) => body,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let signature = sign_relay_response(
        identity,
        &caller,
        context,
        &request_epoch,
        after,
        request_bound,
        &nonce,
        &body,
    );
    let Ok(signature) = HeaderValue::from_str(&encode_hex(&signature)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut http = octet(body);
    http.headers_mut()
        .insert(HeaderName::from_static(RELAY_SIGNATURE_HEADER), signature);
    http
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

fn device_book_signing_input(signer: &DeviceId, nonce: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        DEVICE_BOOK_SIGNING_CONTEXT.len() + signer.as_bytes().len() + nonce.len() + body.len(),
    );
    input.extend_from_slice(DEVICE_BOOK_SIGNING_CONTEXT);
    input.extend_from_slice(signer.as_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(body);
    input
}

fn sign_device_book(identity: &DeviceIdentity, nonce: &[u8; 32], body: &[u8]) -> [u8; 64] {
    let signature = identity.sign(&device_book_signing_input(
        &identity.device_id(),
        nonce,
        body,
    ));
    let signature = signature.normalize_s().unwrap_or(signature);
    let bytes = signature.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

fn verify_device_book(
    expected_peer: DeviceId,
    expected_sec1: &[u8; 33],
    nonce: &[u8; 32],
    body: &[u8],
    signature_hex: &str,
) -> Result<(), TransportError> {
    let derived = DeviceIdentity::device_id_from_sec1(expected_sec1)?;
    if derived != expected_peer {
        return Err(TransportError::IdentityMismatch {
            advertised: expected_peer.to_hex(),
            derived: derived.to_hex(),
        });
    }
    let verifying = VerifyingKey::from_sec1_bytes(expected_sec1)
        .map_err(|_| crate::error::IdentityError::InvalidPublicKey)?;
    let signature_bytes = decode_fixed_hex::<64>(signature_hex)
        .ok_or_else(|| TransportError::Wire("invalid device-book signature header".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| TransportError::Wire("invalid device-book P-256 signature".into()))?;
    if signature.normalize_s().is_some() {
        return Err(TransportError::Wire(
            "device-book signature is not low-S canonical".into(),
        ));
    }
    DeviceIdentity::verify(
        &verifying,
        &device_book_signing_input(&expected_peer, nonce, body),
        &signature,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_relay_signature(
    caller: DeviceId,
    expected_peer: DeviceId,
    expected_sec1: &[u8; 33],
    context: &[u8],
    cursor: RelayCursorV2,
    request_bound: u64,
    nonce: &[u8; 32],
    body: &[u8],
    signature_hex: &str,
) -> Result<(), TransportError> {
    let derived = DeviceIdentity::device_id_from_sec1(expected_sec1)?;
    if derived != expected_peer {
        return Err(TransportError::IdentityMismatch {
            advertised: expected_peer.to_hex(),
            derived: derived.to_hex(),
        });
    }
    let verifying = VerifyingKey::from_sec1_bytes(expected_sec1)
        .map_err(|_| crate::error::IdentityError::InvalidPublicKey)?;
    let signature_bytes = decode_fixed_hex::<64>(signature_hex)
        .ok_or_else(|| TransportError::Wire("invalid relay signature header".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| TransportError::Wire("invalid relay P-256 signature".into()))?;
    if signature.normalize_s().is_some() {
        return Err(TransportError::Wire(
            "relay signature is not low-S canonical".into(),
        ));
    }
    DeviceIdentity::verify(
        &verifying,
        &relay_response_signing_input(
            context,
            &expected_peer,
            &caller,
            &cursor.epoch,
            cursor.after,
            request_bound,
            nonce,
            body,
        ),
        &signature,
    )?;
    Ok(())
}

fn decode_relay_response(
    wire: RelayResponseV2,
    cursor: RelayCursorV2,
    max_entries: usize,
    status_only: bool,
) -> Result<RelayPageV2, TransportError> {
    if wire.v != RELAY_PROTOCOL_VERSION {
        return Err(TransportError::Wire(format!(
            "unsupported relay protocol version {}",
            wire.v
        )));
    }
    if wire.epoch == [0u8; 32] || wire.floor > wire.head {
        return Err(TransportError::Wire("invalid relay stream bounds".into()));
    }
    let cursor_invalid = (cursor.epoch == [0u8; 32] && wire.floor > 0)
        || (cursor.epoch != [0u8; 32] && cursor.epoch != wire.epoch)
        || (cursor.epoch == wire.epoch && (cursor.after < wire.floor || cursor.after > wire.head));
    if wire.reset {
        if !cursor_invalid || !wire.entries.is_empty() || wire.next != wire.floor {
            return Err(TransportError::Wire("invalid relay reset response".into()));
        }
        return Ok(RelayPageV2 {
            epoch: wire.epoch,
            head: wire.head,
            floor: wire.floor,
            next: wire.next,
            reset: true,
            entries: Vec::new(),
        });
    }
    if cursor_invalid {
        return Err(TransportError::Wire(
            "relay response did not reset an invalid cursor".into(),
        ));
    }
    if status_only {
        if !wire.entries.is_empty() || wire.next != cursor.after {
            return Err(TransportError::Wire("invalid relay status response".into()));
        }
    } else {
        if wire.entries.len() > max_entries {
            return Err(TransportError::Wire(
                "relay page exceeds requested limit".into(),
            ));
        }
        let mut previous = cursor.after;
        for entry in &wire.entries {
            if previous.checked_add(1) != Some(entry.seq) || entry.seq > wire.head {
                return Err(TransportError::Wire(
                    "relay sequence is not strictly increasing as a contiguous prefix".into(),
                ));
            }
            previous = entry.seq;
        }
        let expected_next = wire
            .entries
            .last()
            .map(|entry| entry.seq)
            .unwrap_or(cursor.after);
        if wire.next != expected_next || wire.next < wire.floor || wire.next > wire.head {
            return Err(TransportError::Wire(
                "invalid relay page next cursor".into(),
            ));
        }
    }

    let mut entries = Vec::with_capacity(wire.entries.len());
    for entry in wire.entries {
        entries.push(RelayOpV2 {
            seq: entry.seq,
            op: SignedOp::from_bytes(&entry.envelope)?,
        });
    }
    Ok(RelayPageV2 {
        epoch: wire.epoch,
        head: wire.head,
        floor: wire.floor,
        next: wire.next,
        reset: false,
        entries,
    })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Pulls a peer's op-log over HTTP.
pub struct HttpPullSource {
    base_url: String,
    client: reqwest::Client,
    limit: u16,
}

impl HttpPullSource {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            client: build_client(DEFAULT_REQUEST_TIMEOUT),
            limit: DEFAULT_PULL_LIMIT,
        }
    }

    pub fn with_limit(mut self, limit: u16) -> Self {
        self.limit = limit;
        self
    }

    /// Override the per-request timeout (default [`DEFAULT_REQUEST_TIMEOUT`]).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = build_client(timeout);
        self
    }

    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, TransportError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!("status {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TransportError::Http(e.to_string()))
    }

    /// Fetch the peer's device id and verifying key.
    pub async fn fetch_identity(&self) -> Result<IdentityResp, TransportError> {
        let bytes = self
            .get_bytes(&format!("{}/identity", self.base_url))
            .await?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))
    }

    /// Fetch the peer's current log head, for liveness/debug.
    pub async fn fetch_head(&self) -> Result<OrderKey, TransportError> {
        let bytes = self.get_bytes(&format!("{}/head", self.base_url)).await?;
        let arr: [u8; 72] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::Wire("head is not 72 bytes".into()))?;
        Ok(OrderKey::from_wire(&arr))
    }

    /// Long-poll the peer's `/watch`: resolves with the peer head the instant it
    /// differs from `known`, or when the server's hold window closes (returning
    /// the unchanged head). The per-request timeout is `wait + DEFAULT_REQUEST_TIMEOUT`,
    /// so the client never fires before the server replies — the slack absorbs
    /// RTT and server scheduling past the hold window. An old peer without
    /// `/watch` answers 404, surfaced here as `Err`, which the pull loop treats
    /// as "no push; fall back to interval polling" (per-link degradation).
    pub async fn watch_head(
        &self,
        known: OrderKey,
        wait: Duration,
    ) -> Result<OrderKey, TransportError> {
        let url = format!(
            "{}/watch?head={}&wait={}",
            self.base_url,
            encode_order_key(&known),
            wait.as_millis()
        );
        let resp = self
            .client
            .get(&url)
            .timeout(wait + DEFAULT_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!("status {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let arr: [u8; 72] = bytes[..]
            .try_into()
            .map_err(|_| TransportError::Wire("watch head is not 72 bytes".into()))?;
        Ok(OrderKey::from_wire(&arr))
    }

    /// Fetch the peer's trusted device set (D11 transitive key gossip).
    pub async fn fetch_devices(&self) -> Result<DevicesResp, TransportError> {
        let bytes = self
            .get_bytes(&format!("{}/devices", self.base_url))
            .await?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))
    }

    /// Fetch `/devices` and authenticate its exact response bytes with the
    /// already-pinned peer identity before deserializing them. A missing,
    /// malformed, wrong-key, or body-mismatched signature fails closed. Use
    /// [`HttpPullSource::fetch_devices`] for legacy untrusted gossip.
    pub async fn fetch_attested_devices(
        &self,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
    ) -> Result<DevicesResp, TransportError> {
        let mut nonce = [0u8; 32];
        OsRng.try_fill_bytes(&mut nonce).map_err(|e| {
            TransportError::Http(format!("device-book nonce generation failed: {e}"))
        })?;
        let resp = self
            .client
            .get(format!("{}/devices", self.base_url))
            .header(DEVICE_BOOK_NONCE_HEADER, encode_hex(&nonce))
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!("status {}", resp.status())));
        }
        let signature = resp
            .headers()
            .get(DEVICE_BOOK_SIGNATURE_HEADER)
            .ok_or_else(|| {
                TransportError::Wire(format!(
                    "missing {DEVICE_BOOK_SIGNATURE_HEADER} response header"
                ))
            })?
            .to_str()
            .map_err(|_| {
                TransportError::Wire(format!(
                    "invalid {DEVICE_BOOK_SIGNATURE_HEADER} response header"
                ))
            })?
            .to_owned();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        verify_device_book(
            expected_peer,
            expected_public_key_sec1,
            &nonce,
            &bytes,
            &signature,
        )?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_relay_v2(
        &self,
        local_identity: &DeviceIdentity,
        url: String,
        context: &[u8],
        request_context: &[u8],
        request_bound: u64,
        cursor: RelayCursorV2,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        max_entries: usize,
        status_only: bool,
        timeout: Option<Duration>,
    ) -> Result<RelayPageV2, TransportError> {
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| TransportError::Http(format!("relay nonce generation failed: {e}")))?;
        let request_signature = sign_relay_request(
            local_identity,
            request_context,
            &expected_peer,
            &cursor.epoch,
            cursor.after,
            request_bound,
            &nonce,
        );
        let mut request = self
            .client
            .get(url)
            .header(RELAY_NONCE_HEADER, encode_hex(&nonce))
            .header(RELAY_CALLER_HEADER, local_identity.device_id().to_hex())
            .header(
                RELAY_REQUEST_SIGNATURE_HEADER,
                encode_hex(&request_signature),
            );
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED
        ) {
            return Err(TransportError::RelayV2Unsupported {
                status: response.status().as_u16(),
            });
        }
        if !response.status().is_success() {
            return Err(TransportError::Http(format!(
                "status {}",
                response.status()
            )));
        }
        let signature = response
            .headers()
            .get(RELAY_SIGNATURE_HEADER)
            .ok_or_else(|| {
                TransportError::Wire(format!("missing {RELAY_SIGNATURE_HEADER} response header"))
            })?
            .to_str()
            .map_err(|_| {
                TransportError::Wire(format!("invalid {RELAY_SIGNATURE_HEADER} response header"))
            })?
            .to_owned();
        let body = response
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        verify_relay_signature(
            local_identity.device_id(),
            expected_peer,
            expected_public_key_sec1,
            context,
            cursor,
            request_bound,
            &nonce,
            &body,
            &signature,
        )?;
        let wire: RelayResponseV2 =
            postcard::from_bytes(&body).map_err(|e| TransportError::Wire(e.to_string()))?;
        decode_relay_response(wire, cursor, max_entries, status_only)
    }

    /// Pull a bounded, authenticated page from the peer's insertion-ordered v2
    /// relay stream. HTTP 404/501 is surfaced distinctly for diagnostics but
    /// does not authenticate a downgrade to v1.
    pub async fn fetch_relay_ops_v2(
        &self,
        local_identity: &DeviceIdentity,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        cursor: RelayCursorV2,
    ) -> Result<RelayPageV2, TransportError> {
        let url = format!(
            "{}/v2/ops?epoch={}&after={}&limit={}",
            self.base_url,
            encode_hex(&cursor.epoch),
            cursor.after,
            self.limit
        );
        self.request_relay_v2(
            local_identity,
            url,
            RELAY_OPS_SIGNING_CONTEXT,
            RELAY_OPS_REQUEST_CONTEXT,
            self.limit as u64,
            cursor,
            expected_peer,
            expected_public_key_sec1,
            self.limit as usize,
            false,
            None,
        )
        .await
    }

    /// Fetch authenticated relay stream bounds without transferring entries.
    pub async fn fetch_relay_head_v2(
        &self,
        local_identity: &DeviceIdentity,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        cursor: RelayCursorV2,
    ) -> Result<RelayPageV2, TransportError> {
        let url = format!(
            "{}/v2/head?epoch={}&after={}",
            self.base_url,
            encode_hex(&cursor.epoch),
            cursor.after
        );
        self.request_relay_v2(
            local_identity,
            url,
            RELAY_HEAD_SIGNING_CONTEXT,
            RELAY_HEAD_REQUEST_CONTEXT,
            0,
            cursor,
            expected_peer,
            expected_public_key_sec1,
            0,
            true,
            None,
        )
        .await
    }

    /// Long-poll authenticated relay bounds, waking for every unique insertion
    /// even when its semantic [`OrderKey`] is below the existing v1 head.
    pub async fn watch_relay_head_v2(
        &self,
        local_identity: &DeviceIdentity,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        cursor: RelayCursorV2,
        wait: Duration,
    ) -> Result<RelayPageV2, TransportError> {
        let wait = wait.min(WATCH_MAX_WAIT);
        let wait_millis = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let url = format!(
            "{}/v2/watch?epoch={}&after={}&wait={}",
            self.base_url,
            encode_hex(&cursor.epoch),
            cursor.after,
            wait_millis
        );
        self.request_relay_v2(
            local_identity,
            url,
            RELAY_WATCH_SIGNING_CONTEXT,
            RELAY_WATCH_REQUEST_CONTEXT,
            wait_millis,
            cursor,
            expected_peer,
            expected_public_key_sec1,
            0,
            true,
            Some(wait + DEFAULT_REQUEST_TIMEOUT),
        )
        .await
    }
}

/// Build a `reqwest::Client` with a total per-request timeout. `build` only
/// fails if the TLS backend cannot initialize, which the plain-HTTP transport
/// never uses — the same infallible-in-practice contract as `Client::new`.
fn build_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("reqwest client build")
}

impl PullSource for HttpPullSource {
    type Error = TransportError;

    async fn pull(&self, since: Cursor) -> Result<Vec<SignedOp>, Self::Error> {
        let url = format!(
            "{}/ops?since={}&limit={}",
            self.base_url,
            encode_order_key(&since),
            self.limit
        );
        let bytes = self.get_bytes(&url).await?;
        let resp: PullResponse =
            postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))?;
        let mut ops = Vec::with_capacity(resp.ops.len());
        for raw in &resp.ops {
            ops.push(SignedOp::from_bytes(raw)?);
        }
        Ok(ops)
    }
}

// ---------------------------------------------------------------------------
// Pull loop
// ---------------------------------------------------------------------------

/// Fetch a peer's `/identity`, check its advertised device id against the key it
/// serves, register the key, and return the peer's device id plus whether this
/// call newly introduced the key (false when it was already registered, e.g.
/// loaded from persisted peer keys). A peer whose key does not derive its
/// advertised id is refused. The newly-introduced flag lets a caller that fails
/// to persist the key roll back exactly what this call added and nothing else.
pub async fn register_peer(
    source: &HttpPullSource,
    registry: &Mutex<DeviceRegistry>,
) -> Result<(DeviceId, bool), TransportError> {
    let (peer, _, newly_added) = register_peer_with_key(source, registry).await?;
    Ok((peer, newly_added))
}

/// Register a peer and retain the exact verified key for authenticated relay
/// requests. The returned key is pinned to the returned [`DeviceId`] for the
/// lifetime of the caller's link.
pub async fn register_peer_with_key(
    source: &HttpPullSource,
    registry: &Mutex<DeviceRegistry>,
) -> Result<(DeviceId, [u8; 33], bool), TransportError> {
    let resp = source.fetch_identity().await?;
    let advertised = DeviceId::from_bytes(resp.device_id);
    let sec1: [u8; 33] = resp
        .public_key_sec1
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::Wire("public key is not 33 bytes".into()))?;
    let derived = DeviceIdentity::device_id_from_sec1(&sec1)?;
    if derived != advertised {
        return Err(TransportError::IdentityMismatch {
            advertised: advertised.to_hex(),
            derived: derived.to_hex(),
        });
    }
    // The network fetch is done; take the lock only for the synchronous insert
    // so a slow /identity round-trip never blocks the /devices route that reads
    // the same registry.
    let mut registry = registry.lock().expect("registry mutex poisoned");
    let newly_added = !registry.contains(&advertised);
    registry.insert_sec1(&sec1)?;
    Ok((advertised, sec1, newly_added))
}

/// Fetch a peer's `/devices` set and register every valid, not-yet-known key.
/// This is transitive-trust-by-gossip (D11): device C's key reaches puller D
/// through peer B even though D never contacted C. Each entry is admitted only
/// if its key derives its advertised id — the exact [`SignedOp::verify`] device
/// check — so a peer can introduce its own fabricated devices (which can only
/// sign their own ops) but can never forge a mapping for a device it does not
/// control. Malformed or mismatched entries are skipped, not fatal, so one bad
/// row cannot deny learning the rest of an N-node mesh.
///
/// Returns the device ids newly added, so a caller that fails to persist the
/// keys can roll back exactly what this introduced — the same durability
/// discipline as [`register_peer`]: a key must be durable before it is allowed
/// to verify an op (or a cursor could advance past ops the next restart cannot
/// verify).
pub async fn learn_devices(
    source: &HttpPullSource,
    registry: &Mutex<DeviceRegistry>,
) -> Result<Vec<DeviceId>, TransportError> {
    let resp = source.fetch_devices().await?;
    Ok(learn_device_entries(resp, registry))
}

/// Authenticate a peer's exact `/devices` response with its pinned key before
/// admitting any advertised signer. This is the production relay-v2 trust
/// path; [`learn_devices`] remains available for explicitly legacy v1 callers.
pub async fn learn_attested_devices(
    source: &HttpPullSource,
    expected_peer: DeviceId,
    expected_public_key_sec1: &[u8; 33],
    registry: &Mutex<DeviceRegistry>,
) -> Result<Vec<DeviceId>, TransportError> {
    let resp = source
        .fetch_attested_devices(expected_peer, expected_public_key_sec1)
        .await?;
    Ok(learn_device_entries(resp, registry))
}

fn learn_device_entries(resp: DevicesResp, registry: &Mutex<DeviceRegistry>) -> Vec<DeviceId> {
    let mut registry = registry.lock().expect("registry mutex poisoned");
    let mut added = Vec::new();
    for entry in resp.devices {
        let advertised = DeviceId::from_bytes(entry.device_id);
        let Ok(sec1) = <[u8; 33]>::try_from(entry.public_key_sec1.as_slice()) else {
            continue;
        };
        let Ok(derived) = DeviceIdentity::device_id_from_sec1(&sec1) else {
            continue;
        };
        if derived != advertised || registry.contains(&advertised) {
            continue;
        }
        if registry.insert_sec1(&sec1).is_ok() {
            added.push(advertised);
        }
    }
    added
}

/// How [`sync_once_with`] pushes newly-crossed ops into the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// Re-apply the whole log whenever the cursor moves. Correct for a store
    /// that resolves conflicts by arrival order (the reference
    /// [`crate::kv::KvStore`]); O(history) per pull.
    Replay,
    /// Apply only the ops the cursor newly crossed (G1). O(batch) per pull, for
    /// a store with an internal per-row version guard (Grand Central's proxy.db
    /// adapter) that stays convergent under out-of-order-across-batches arrival.
    Incremental,
}

/// One incremental pull from `source`, applying with [`ApplyMode::Replay`].
/// Backwards-compatible shim over [`sync_once_with`].
#[allow(clippy::too_many_arguments)]
pub async fn sync_once<S, P>(
    source: &P,
    registry: &Mutex<DeviceRegistry>,
    clock: &NodeClock,
    log: &Mutex<OpLog>,
    store: &Mutex<S>,
    cursor: &mut OrderKey,
    durability: Option<&Mutex<OplogWriter>>,
) -> Result<usize, TransportError>
where
    S: Store,
    P: PullSource<Error = TransportError>,
{
    sync_once_with(
        source,
        registry,
        clock,
        log,
        store,
        cursor,
        durability,
        ApplyMode::Replay,
    )
    .await
}

/// One incremental pull from `source`. Each returned op is verified against the
/// device registry (a peer serves ops from several devices, including the
/// puller's own echoed back), its HLC folded into the local clock, and new ops
/// appended — persisted when `durability` is set. Newly-crossed ops are then
/// pushed into the store per `mode`.
///
/// `cursor` only advances over ops that were actually verified and applied (or
/// verified and skipped as genuine duplicates). The first op that fails
/// verification or the drift guard aborts the batch: the cursor is left at the
/// last verified op and a [`TransportError`] naming the offending device is
/// returned, so a forged op with a huge order key can never poison the durable
/// cursor and skip later legitimate ops. Returns the number of newly appended
/// ops on success.
#[allow(clippy::too_many_arguments)]
pub async fn sync_once_with<S, P>(
    source: &P,
    registry: &Mutex<DeviceRegistry>,
    clock: &NodeClock,
    log: &Mutex<OpLog>,
    store: &Mutex<S>,
    cursor: &mut OrderKey,
    durability: Option<&Mutex<OplogWriter>>,
    mode: ApplyMode,
) -> Result<usize, TransportError>
where
    S: Store,
    P: PullSource<Error = TransportError>,
{
    let ops = source.pull(*cursor).await?;
    let mut appended = 0;
    let mut highest = *cursor;
    // The first op that fails a check aborts the batch. Ops before it are fully
    // verified-and-applied (or verified genuine duplicates), so the cursor may
    // advance over them; the offending op and everything after it are not
    // reached, so the cursor never moves past the failure point.
    let mut abort: Option<TransportError> = None;
    {
        // Lock the registry read-side only for the synchronous verification
        // loop (the network pull already completed above), keeping the /devices
        // route responsive while a batch verifies.
        let registry = registry.lock().expect("registry mutex poisoned");
        let mut log = log.lock().expect("oplog mutex poisoned");
        for op in ops {
            let key = op.order_key();
            // A device we cannot verify (unknown key) or an op whose signature
            // does not check out never enters the log and does not move the
            // cursor. Abort so a forged op with a huge order key cannot poison
            // the durable cursor and permanently skip later legitimate ops.
            let Some(verifying) = registry.key_for(&op.body.device) else {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: "unknown device".into(),
                });
                break;
            };
            if let Err(e) = op.verify(verifying) {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: e.to_string(),
                });
                break;
            }
            // Fold the remote reading. A drift rejection is fatal to the op: it
            // must not enter the log, so treat it like a verification failure
            // and stop before appending or advancing past it.
            if let Err(e) = clock.update(op.body.hlc, &op.body.device) {
                abort = Some(TransportError::Drift {
                    device: op.body.device.to_hex(),
                    hlc: op.body.hlc.0,
                    reason: e.to_string(),
                });
                break;
            }
            // Durable append FIRST, memory second. A failed durable write must
            // not leave a memory-only op behind: on retry it would read as a
            // verified duplicate and advance the cursor past an op the durable
            // log never received, losing it across a crash.
            if !log.contains(&op.id) {
                if let Some(writer) = durability {
                    if let Err(e) = writer.lock().expect("oplog writer poisoned").append(&op) {
                        abort = Some(e.into());
                        break;
                    }
                }
                log.append(op.clone());
                appended += 1;
            }
            // Verified and applied, or a verified genuine duplicate: safe to
            // advance the cursor over this op.
            highest = key;
        }
    }
    // Force the op-log to disk BEFORE the cursor is allowed to advance at all
    // (the caller persists the cursor once this returns). Syncing whenever the
    // cursor moves — not just when this batch wrote — also covers the retry
    // path where ops written by a previous call advance the cursor as verified
    // duplicates after that call's fsync failed.
    if highest != *cursor {
        if let Some(writer) = durability {
            writer
                .lock()
                .expect("oplog writer poisoned")
                .sync_after_batch()?;
        }
    }
    // Apply whenever the cursor moves, not only when this batch appended: after
    // a failed fsync, the retry sees the batch's ops as verified duplicates
    // (appended == 0) yet still advances the cursor, and the store must not be
    // left behind the log. Both apply paths are idempotent, so re-running over
    // duplicates is safe. Incremental scopes the work to `(cursor, highest]` —
    // exactly the ops just crossed, including any a prior aborted fsync left
    // behind — instead of re-walking the whole log.
    if highest != *cursor {
        let log = log.lock().expect("oplog mutex poisoned");
        let mut store = store.lock().expect("store mutex poisoned");
        match mode {
            ApplyMode::Replay => {
                replay(&log, &mut *store).map_err(|e| TransportError::Replay(e.to_string()))?;
            }
            ApplyMode::Incremental => {
                apply_range(&log, &mut *store, *cursor, highest)
                    .map_err(|e| TransportError::Replay(e.to_string()))?;
            }
        }
    }
    *cursor = highest;
    match abort {
        Some(e) => Err(e),
        None => Ok(appended),
    }
}

/// Result of one authenticated insertion-order relay pull.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelaySyncOutcome {
    /// Entries whose embedded operation signature and clock were accepted.
    pub received: usize,
    /// Accepted operations that were not already in the local log.
    pub appended: usize,
    /// The peer authenticated a different stream epoch or retention floor.
    pub reset: bool,
}

/// Pull one authenticated relay-v2 page from a pinned peer. Relay sequence is
/// used only for transport completeness; verified operations still enter the
/// semantic [`OpLog`] and the store is replayed in [`OrderKey`] order.
///
/// Durable append precedes memory append, fsync precedes cursor advancement,
/// and the first rejected entry aborts without crossing its relay sequence.
#[allow(clippy::too_many_arguments)]
pub async fn sync_relay_once_v2<S>(
    source: &HttpPullSource,
    local_identity: &DeviceIdentity,
    expected_peer: DeviceId,
    expected_public_key_sec1: &[u8; 33],
    registry: &Mutex<DeviceRegistry>,
    clock: &NodeClock,
    log: &Mutex<OpLog>,
    store: &Mutex<S>,
    cursor: &mut RelayCursorV2,
    durability: Option<&Mutex<OplogWriter>>,
) -> Result<RelaySyncOutcome, TransportError>
where
    S: Store,
{
    let page = source
        .fetch_relay_ops_v2(
            local_identity,
            expected_peer,
            expected_public_key_sec1,
            *cursor,
        )
        .await?;
    if page.reset {
        *cursor = page.cursor();
        return Ok(RelaySyncOutcome {
            reset: true,
            ..RelaySyncOutcome::default()
        });
    }

    let initial = *cursor;
    let mut after = initial.after;
    let mut received = 0;
    let mut appended = 0;
    let mut abort = None;
    {
        let registry = registry.lock().expect("registry mutex poisoned");
        let mut log = log.lock().expect("oplog mutex poisoned");
        for entry in page.entries {
            let op = entry.op;
            let Some(verifying) = registry.key_for(&op.body.device) else {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: "unknown device".into(),
                });
                break;
            };
            if let Err(e) = op.verify(verifying) {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: e.to_string(),
                });
                break;
            }
            if let Err(e) = clock.update(op.body.hlc, &op.body.device) {
                abort = Some(TransportError::Drift {
                    device: op.body.device.to_hex(),
                    hlc: op.body.hlc.0,
                    reason: e.to_string(),
                });
                break;
            }
            if !log.contains(&op.id) {
                if let Some(writer) = durability {
                    if let Err(e) = writer.lock().expect("oplog writer poisoned").append(&op) {
                        abort = Some(e.into());
                        break;
                    }
                }
                log.append(op);
                appended += 1;
            }
            after = entry.seq;
            received += 1;
        }
    }

    if after != initial.after {
        if let Some(writer) = durability {
            writer
                .lock()
                .expect("oplog writer poisoned")
                .sync_after_batch()?;
        }
        let log = log.lock().expect("oplog mutex poisoned");
        let mut store = store.lock().expect("store mutex poisoned");
        replay(&log, &mut *store).map_err(|e| TransportError::Replay(e.to_string()))?;
    }
    *cursor = RelayCursorV2 {
        epoch: page.epoch,
        after,
    };
    match abort {
        Some(error) => Err(error),
        None => Ok(RelaySyncOutcome {
            received,
            appended,
            reset: false,
        }),
    }
}

// ---------------------------------------------------------------------------
// Cursor persistence (D2.6): one 72-byte file per peer.
// ---------------------------------------------------------------------------

fn cursor_path(data_dir: &Path, peer: &DeviceId) -> PathBuf {
    data_dir
        .join("cursors")
        .join(format!("{}.cursor", peer.to_hex()))
}

/// Load a peer's persisted cursor, or [`OrderKey::MIN`] if none exists yet.
pub fn load_cursor(data_dir: &Path, peer: &DeviceId) -> OrderKey {
    match std::fs::read(cursor_path(data_dir, peer)) {
        Ok(bytes) => match <[u8; 72]>::try_from(bytes.as_slice()) {
            Ok(arr) => OrderKey::from_wire(&arr),
            Err(_) => OrderKey::MIN,
        },
        Err(_) => OrderKey::MIN,
    }
}

/// Persist a peer's cursor durably: write the temp file and fsync it, rename it
/// over the live cursor, then (on unix) fsync the containing directory so the
/// rename itself survives a crash. Callers only ever pass a cursor that sits at
/// or before the last op already fsynced into the op-log, so a recovered cursor
/// can never point past ops the log has lost.
pub fn save_cursor(data_dir: &Path, peer: &DeviceId, cursor: OrderKey) -> std::io::Result<()> {
    let path = cursor_path(data_dir, peer);
    let dir = path
        .parent()
        .expect("cursor path always has a `cursors` parent");
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("cursor.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&cursor.to_wire())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    fsync_dir(dir)
}

fn relay_cursor_path(data_dir: &Path, peer: &DeviceId) -> PathBuf {
    data_dir
        .join("cursors")
        .join(format!("{}.relay-v2.cursor", peer.to_hex()))
}

/// Load a peer's persisted `(epoch, relay sequence)` cursor. Missing, corrupt,
/// or internally invalid files restart at sequence zero and cannot inherit a
/// legacy semantic cursor.
pub fn load_relay_cursor(data_dir: &Path, peer: &DeviceId) -> RelayCursorV2 {
    let Ok(bytes) = std::fs::read(relay_cursor_path(data_dir, peer)) else {
        return RelayCursorV2::START;
    };
    if bytes.len() != 40 {
        return RelayCursorV2::START;
    }
    let mut epoch = [0u8; 32];
    epoch.copy_from_slice(&bytes[..32]);
    let mut after = [0u8; 8];
    after.copy_from_slice(&bytes[32..]);
    let after = u64::from_be_bytes(after);
    if epoch == [0u8; 32] && after != 0 {
        return RelayCursorV2::START;
    }
    RelayCursorV2 { epoch, after }
}

/// Durably persist a relay-v2 cursor in a file distinct from the v1 semantic
/// cursor, so first v2 contact always starts from sequence zero.
pub fn save_relay_cursor(
    data_dir: &Path,
    peer: &DeviceId,
    cursor: RelayCursorV2,
) -> std::io::Result<()> {
    let path = relay_cursor_path(data_dir, peer);
    let dir = path
        .parent()
        .expect("relay cursor path always has a `cursors` parent");
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("cursor.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&cursor.epoch)?;
        file.write_all(&cursor.after.to_be_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    fsync_dir(dir)
}

/// fsync a directory so a rename into it is durable. No portable equivalent
/// exists on Windows; the temp file was fsynced and the rename is best-effort
/// atomic there, which is documented as the accepted weaker guarantee.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Peer-key persistence: known verifying keys must be loadable BEFORE the
// startup op-log replay, or previously fsynced peer ops read as unknown-device
// frames and are dropped from memory while the persisted cursors say they were
// already pulled.
// ---------------------------------------------------------------------------

fn peers_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peers.bin")
}

fn relay_callers_path(data_dir: &Path) -> PathBuf {
    data_dir.join("relay-callers.bin")
}

/// Load persisted peer keys into the registry. Returns how many registered.
/// Missing or unreadable entries are skipped: worst case the op stays on disk
/// and is recovered by a later replay once the key is known again.
pub fn load_peer_keys(data_dir: &Path, registry: &mut DeviceRegistry) -> usize {
    load_keys(&peers_path(data_dir), registry)
}

/// Load the direct relay-caller allowlist. It is intentionally distinct from
/// `peers.bin`, which also carries transitively vouched historical signers.
pub fn load_relay_caller_keys(data_dir: &Path, registry: &mut DeviceRegistry) -> usize {
    load_keys(&relay_callers_path(data_dir), registry)
}

fn load_keys(path: &Path, registry: &mut DeviceRegistry) -> usize {
    let Ok(bytes) = std::fs::read(path) else {
        return 0;
    };
    let Ok(keys) = postcard::from_bytes::<Vec<Vec<u8>>>(&bytes) else {
        return 0;
    };
    let mut n = 0;
    for key in keys {
        if let Ok(sec1) = <[u8; 33]>::try_from(key.as_slice()) {
            if registry.insert_sec1(&sec1).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// Persist every key in the registry with the same fsync discipline as
/// [`save_cursor`], so the keys survive to the next startup's replay.
pub fn save_peer_keys(data_dir: &Path, registry: &DeviceRegistry) -> std::io::Result<()> {
    save_keys(&peers_path(data_dir), registry)
}

/// Persist only direct relay callers, never transitive `/devices` entries.
pub fn save_relay_caller_keys(data_dir: &Path, registry: &DeviceRegistry) -> std::io::Result<()> {
    save_keys(&relay_callers_path(data_dir), registry)
}

fn save_keys(path: &Path, registry: &DeviceRegistry) -> std::io::Result<()> {
    let keys: Vec<Vec<u8>> = registry.sec1_keys().iter().map(|k| k.to_vec()).collect();
    let bytes = postcard::to_allocvec(&keys)
        .map_err(|e| std::io::Error::other(format!("encode peer keys: {e}")))?;
    let dir = path.parent().expect("key path always has a parent");
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("bin.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    fsync_dir(dir)
}

// ---------------------------------------------------------------------------
// Order-key hex codec for the `since` query param.
// ---------------------------------------------------------------------------

fn encode_order_key(key: &OrderKey) -> String {
    let bytes = key.to_wire();
    let mut s = String::with_capacity(144);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    s
}

fn decode_order_key(s: &str) -> Option<OrderKey> {
    if s.len() != 144 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut wire = [0u8; 72];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        wire[i] = (hex_val(chunk[0])? << 4) | hex_val(chunk[1])?;
    }
    Some(OrderKey::from_wire(&wire))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0f));
    }
    encoded
}

fn decode_fixed_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    if encoded.len() != N * 2 {
        return None;
    }
    let mut decoded = [0u8; N];
    for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_val(chunk[0])? << 4) | hex_val(chunk[1])?;
    }
    Some(decoded)
}

fn hex_digit(nibble: u8) -> char {
    b"0123456789abcdef"[nibble as usize] as char
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use axum::routing::get;

    use super::*;
    use crate::hlc::Hlc;
    use crate::identity::DeviceIdentity;
    use crate::kv::{KvOp, KvStore, kv_store_id};
    use crate::op::{ENVELOPE_VERSION, OpBody, OpId, StoreId};
    use crate::registry::DeviceRegistry;
    use crate::store::Store;

    async fn spawn_app(app: Router) -> HttpPullSource {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        HttpPullSource::new(format!("http://{addr}"))
    }

    async fn spawn_devices_response(
        body: Vec<u8>,
        signed_body: Option<Vec<u8>>,
        signer: Option<Arc<DeviceIdentity>>,
    ) -> HttpPullSource {
        let app = Router::new().route(
            "/devices",
            get(move |headers: HeaderMap| {
                let body = body.clone();
                let signed_body = signed_body.clone();
                let signer = signer.clone();
                async move {
                    let mut response = octet(body);
                    if let (Some(signed_body), Some(signer)) = (signed_body, signer) {
                        let nonce = headers
                            .get(DEVICE_BOOK_NONCE_HEADER)
                            .and_then(|value| value.to_str().ok())
                            .and_then(decode_fixed_hex::<32>)
                            .expect("attested client must send a valid nonce");
                        let signature =
                            encode_hex(&sign_device_book(&signer, &nonce, &signed_body));
                        response.headers_mut().insert(
                            HeaderName::from_static(DEVICE_BOOK_SIGNATURE_HEADER),
                            HeaderValue::from_str(&signature).unwrap(),
                        );
                    }
                    response
                }
            }),
        );
        spawn_app(app).await
    }

    fn encoded_devices(devices: &[&DeviceIdentity]) -> Vec<u8> {
        postcard::to_allocvec(&DevicesResp {
            devices: devices
                .iter()
                .map(|identity| DeviceEntry {
                    device_id: *identity.device_id().as_bytes(),
                    public_key_sec1: identity.public_key_sec1().to_vec(),
                })
                .collect(),
        })
        .unwrap()
    }

    fn encoded_relay_response(
        epoch: [u8; 32],
        head: u64,
        next: u64,
        entries: Vec<RelayWireEntryV2>,
    ) -> Vec<u8> {
        postcard::to_allocvec(&RelayResponseV2 {
            v: RELAY_PROTOCOL_VERSION,
            epoch,
            head,
            floor: 0,
            next,
            reset: false,
            entries,
        })
        .unwrap()
    }

    async fn spawn_relay_ops_response(
        body: Vec<u8>,
        signed_body: Vec<u8>,
        signer: Arc<DeviceIdentity>,
        cursor: RelayCursorV2,
        limit: u16,
        signing_nonce: Option<[u8; 32]>,
    ) -> HttpPullSource {
        let app = Router::new().route(
            "/v2/ops",
            get(move |headers: HeaderMap| {
                let body = body.clone();
                let signed_body = signed_body.clone();
                let signer = signer.clone();
                async move {
                    let request_nonce = headers
                        .get(RELAY_NONCE_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(decode_fixed_hex::<32>)
                        .expect("v2 client must send a valid nonce");
                    let caller = headers
                        .get(RELAY_CALLER_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(decode_fixed_hex::<32>)
                        .map(DeviceId::from_bytes)
                        .expect("v2 client must send a valid caller id");
                    let nonce = signing_nonce.unwrap_or(request_nonce);
                    let signature = sign_relay_response(
                        &signer,
                        &caller,
                        RELAY_OPS_SIGNING_CONTEXT,
                        &cursor.epoch,
                        cursor.after,
                        limit as u64,
                        &nonce,
                        &signed_body,
                    );
                    let mut response = octet(body);
                    response.headers_mut().insert(
                        HeaderName::from_static(RELAY_SIGNATURE_HEADER),
                        HeaderValue::from_str(&encode_hex(&signature)).unwrap(),
                    );
                    response
                }
            }),
        );
        spawn_app(app).await.with_limit(limit)
    }

    async fn raw_relay_ops_request(
        client: &HttpPullSource,
        caller: &DeviceIdentity,
        serving_peer: DeviceId,
        cursor: RelayCursorV2,
        signed_limit: u16,
        url_limit: u16,
        nonce: [u8; 32],
    ) -> reqwest::Response {
        let signature = sign_relay_request(
            caller,
            RELAY_OPS_REQUEST_CONTEXT,
            &serving_peer,
            &cursor.epoch,
            cursor.after,
            signed_limit as u64,
            &nonce,
        );
        client
            .client
            .get(format!(
                "{}/v2/ops?epoch={}&after={}&limit={url_limit}",
                client.base_url,
                encode_hex(&cursor.epoch),
                cursor.after,
            ))
            .header(RELAY_NONCE_HEADER, encode_hex(&nonce))
            .header(RELAY_CALLER_HEADER, caller.device_id().to_hex())
            .header(RELAY_REQUEST_SIGNATURE_HEADER, encode_hex(&signature))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn attested_devices_verify_serving_peer_and_keep_legacy_body() {
        let serving = Arc::new(DeviceIdentity::generate());
        let historical = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*historical.verifying_key());
        let app = router(ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            Arc::new(Mutex::new(registry)),
        ));
        let client = spawn_app(app).await;

        let legacy = client.fetch_devices().await.unwrap();
        assert_eq!(legacy.devices.len(), 2, "legacy postcard body is unchanged");

        let attested = client
            .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
            .await
            .unwrap();
        assert_eq!(attested.devices.len(), 2);
        assert!(
            attested
                .devices
                .iter()
                .any(|entry| entry.device_id == *historical.device_id().as_bytes())
        );
    }

    #[tokio::test]
    async fn attested_devices_reject_tampered_body() {
        let serving = Arc::new(DeviceIdentity::generate());
        let original = encoded_devices(&[&serving]);
        let injected = DeviceIdentity::generate();
        let tampered = encoded_devices(&[&serving, &injected]);
        let client =
            spawn_devices_response(tampered, Some(original), Some(Arc::clone(&serving))).await;

        let error = client
            .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn attested_devices_reject_wrong_signature() {
        let serving = DeviceIdentity::generate();
        let attacker = Arc::new(DeviceIdentity::generate());
        let body = encoded_devices(&[&serving]);
        let client =
            spawn_devices_response(body.clone(), Some(body), Some(Arc::clone(&attacker))).await;

        let error = client
            .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn attested_devices_reject_wrong_pinned_key() {
        let serving = Arc::new(DeviceIdentity::generate());
        let wrong_peer = DeviceIdentity::generate();
        let body = encoded_devices(&[&serving]);
        let client =
            spawn_devices_response(body.clone(), Some(body), Some(Arc::clone(&serving))).await;

        let error = client
            .fetch_attested_devices(wrong_peer.device_id(), &wrong_peer.public_key_sec1())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn attested_devices_reject_missing_signature_header() {
        let serving = DeviceIdentity::generate();
        let client = spawn_devices_response(encoded_devices(&[&serving]), None, None).await;

        let error = client
            .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
            .await
            .unwrap_err();
        assert!(
            matches!(error, TransportError::Wire(message) if message.contains("missing x-proxy-device-book-signature"))
        );
    }

    #[test]
    fn attested_devices_reject_replayed_signature_for_a_different_nonce() {
        let serving = DeviceIdentity::generate();
        let body = encoded_devices(&[&serving]);
        let original_nonce = [0x11; 32];
        let next_nonce = [0x22; 32];
        let replayed_signature = encode_hex(&sign_device_book(&serving, &original_nonce, &body));

        let error = verify_device_book(
            serving.device_id(),
            &serving.public_key_sec1(),
            &next_nonce,
            &body,
            &replayed_signature,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[derive(Clone)]
    struct FailingDeviceBook;

    impl DeviceBook for FailingDeviceBook {
        fn known_devices(&self) -> Vec<(DeviceId, [u8; 33])> {
            panic!("serving must use the fallible device-book read")
        }

        fn try_known_devices(&self) -> Result<Vec<(DeviceId, [u8; 33])>, String> {
            Err("database read failed".into())
        }
    }

    #[derive(Clone)]
    struct StateOnlyRelayLog {
        log: Arc<Mutex<OpLog>>,
        page_calls: Arc<AtomicUsize>,
    }

    impl LogSource for StateOnlyRelayLog {
        fn since(&self, cursor: OrderKey, limit: usize) -> Vec<SignedOp> {
            self.log
                .lock()
                .unwrap()
                .since(cursor)
                .take(limit)
                .cloned()
                .collect()
        }

        fn head(&self) -> Option<OrderKey> {
            self.log.lock().unwrap().head()
        }

        fn contains(&self, id: &OpId) -> bool {
            self.log.lock().unwrap().contains(id)
        }

        fn relay_state(&self) -> Result<Option<RelayStreamState>, String> {
            Ok(Some(self.log.lock().unwrap().relay_state()))
        }

        fn relay_page(
            &self,
            _after: u64,
            _limit: usize,
        ) -> Result<Option<crate::log::RelayLogPage>, String> {
            self.page_calls.fetch_add(1, AtomicOrdering::Relaxed);
            Err("relay page must not be queried".into())
        }
    }

    #[tokio::test]
    async fn devices_source_failure_is_not_signed_as_an_empty_book() {
        let serving = Arc::new(DeviceIdentity::generate());
        let app = router(ServeState::new(
            serving,
            Arc::new(Mutex::new(OpLog::new())),
            FailingDeviceBook,
        ));
        let client = spawn_app(app).await;

        let response = client
            .client
            .get(format!("{}/devices", client.base_url))
            .header(DEVICE_BOOK_NONCE_HEADER, encode_hex(&[0x33; 32]))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response
                .headers()
                .get(DEVICE_BOOK_SIGNATURE_HEADER)
                .is_none()
        );
    }

    #[tokio::test]
    async fn relay_v2_invalid_cursor_resets_before_querying_page() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let page_calls = Arc::new(AtomicUsize::new(0));
        let source = StateOnlyRelayLog {
            log: Arc::new(Mutex::new(OpLog::new())),
            page_calls: Arc::clone(&page_calls),
        };
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*caller.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            source,
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        let state = client
            .fetch_relay_head_v2(
                &caller,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap();
        let reset = client
            .fetch_relay_ops_v2(
                &caller,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2 {
                    epoch: state.epoch,
                    after: u64::MAX,
                },
            )
            .await
            .unwrap();

        assert!(reset.reset);
        assert_eq!(reset.next, reset.floor);
        assert_eq!(page_calls.load(AtomicOrdering::Relaxed), 0);
    }

    #[tokio::test]
    async fn relay_v2_rejects_oversized_page_before_querying_source() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let page_calls = Arc::new(AtomicUsize::new(0));
        let source = StateOnlyRelayLog {
            log: Arc::new(Mutex::new(OpLog::new())),
            page_calls: Arc::clone(&page_calls),
        };
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*caller.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            source,
            Arc::new(Mutex::new(registry)),
        )))
        .await
        .with_limit(DEFAULT_PULL_LIMIT + 1);

        let error = client
            .fetch_relay_ops_v2(
                &caller,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, TransportError::Http(message) if message == "status 400 Bad Request")
        );
        assert_eq!(page_calls.load(AtomicOrdering::Relaxed), 0);
    }

    #[tokio::test]
    async fn relay_v2_rejects_unknown_caller_without_signed_response() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        let response = raw_relay_ops_request(
            &client,
            &caller,
            serving.device_id(),
            RelayCursorV2::START,
            1,
            1,
            [0x31; 32],
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
    }

    #[tokio::test]
    async fn relay_v2_fails_closed_when_caller_lookup_fails() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            FailingDeviceBook,
        )))
        .await;

        let response = raw_relay_ops_request(
            &client,
            &caller,
            serving.device_id(),
            RelayCursorV2::START,
            1,
            1,
            [0x32; 32],
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
    }

    #[tokio::test]
    async fn relay_v2_rejects_request_query_tampering() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*caller.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        let response = raw_relay_ops_request(
            &client,
            &caller,
            serving.device_id(),
            RelayCursorV2::START,
            1,
            2,
            [0x33; 32],
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
    }

    #[tokio::test]
    async fn relay_v2_rejects_a_replayed_authenticated_request() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*caller.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            Arc::new(Mutex::new(registry)),
        )))
        .await;
        let nonce = [0x34; 32];

        let first = raw_relay_ops_request(
            &client,
            &caller,
            serving.device_id(),
            RelayCursorV2::START,
            1,
            1,
            nonce,
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let replay = raw_relay_ops_request(
            &client,
            &caller,
            serving.device_id(),
            RelayCursorV2::START,
            1,
            1,
            nonce,
        )
        .await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        assert!(replay.headers().get(RELAY_SIGNATURE_HEADER).is_none());
    }

    #[tokio::test]
    async fn relay_v2_never_evicts_an_unexpired_replay_nonce_at_capacity() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*caller.verifying_key());
        let state = ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            Arc::new(Mutex::new(registry)),
        );
        {
            let mut replays = state.relay_replays.lock().unwrap();
            for index in 0..RELAY_REPLAY_LIMIT {
                let mut nonce = [0u8; 32];
                nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
                replays.insert((caller.device_id(), nonce), Instant::now());
            }
        }
        let client = spawn_app(router(state)).await;

        let response = raw_relay_ops_request(
            &client,
            &caller,
            serving.device_id(),
            RelayCursorV2::START,
            1,
            1,
            [0xff; 32],
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
    }

    #[tokio::test]
    async fn relay_v2_delivers_a_late_lower_order_key_by_arrival_sequence() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let high = seal_kv_op(&author, Hlc(30), "high", b"first");
        let low = seal_kv_op(&author, Hlc(10), "low", b"late");
        assert!(low.order_key() < high.order_key());

        let log = Arc::new(Mutex::new(OpLog::new()));
        log.lock().unwrap().append(high.clone());
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*author.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            Arc::clone(&log),
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        let first = client
            .fetch_relay_ops_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap();
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].seq, 1);
        assert_eq!(first.entries[0].op.id, high.id);
        let status = client
            .fetch_relay_head_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                first.cursor(),
            )
            .await
            .unwrap();
        assert_eq!(status.head, 1);
        assert_eq!(status.next, 1);
        assert!(status.entries.is_empty());

        log.lock().unwrap().append(low.clone());
        let late = client
            .fetch_relay_ops_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                first.cursor(),
            )
            .await
            .unwrap();
        assert_eq!(late.entries.len(), 1);
        assert_eq!(late.entries[0].seq, 2);
        assert_eq!(late.entries[0].op.id, low.id);
    }

    #[tokio::test]
    async fn relay_v2_epoch_mismatch_returns_authenticated_reset() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let log = Arc::new(Mutex::new(OpLog::new()));
        log.lock()
            .unwrap()
            .append(seal_kv_op(&author, Hlc(10), "k", b"v"));
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*author.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            log,
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        let reset = client
            .fetch_relay_ops_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2 {
                    epoch: [0x99; 32],
                    after: 1,
                },
            )
            .await
            .unwrap();
        assert!(reset.reset);
        assert!(reset.entries.is_empty());
        assert_eq!(reset.next, reset.floor);
        assert_ne!(reset.epoch, [0x99; 32]);
    }

    #[tokio::test]
    async fn relay_v2_watch_wakes_for_a_unique_late_lower_order_key() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let high = seal_kv_op(&author, Hlc(30), "high", b"first");
        let low = seal_kv_op(&author, Hlc(10), "low", b"late");
        let semantic_head = high.order_key();
        assert!(low.order_key() < semantic_head);

        let log = Arc::new(Mutex::new(OpLog::new()));
        log.lock().unwrap().append(high);
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*author.verifying_key());
        let publisher = HeadPublisher::new(semantic_head);
        let client = spawn_app(router(
            ServeState::new(
                Arc::clone(&serving),
                Arc::clone(&log),
                Arc::new(Mutex::new(registry)),
            )
            .with_watch(publisher.watch()),
        ))
        .await;
        let first = client
            .fetch_relay_ops_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap();
        assert_eq!(first.head, 1);

        let append_log = Arc::clone(&log);
        let appender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            assert!(append_log.lock().unwrap().append(low));
            publisher.publish(semantic_head);
        });
        let start = Instant::now();
        let observed = client
            .watch_relay_head_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                first.cursor(),
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        appender.await.unwrap();

        assert_eq!(observed.head, 2);
        assert_eq!(observed.next, 1, "watch must not advance the pull cursor");
        assert!(observed.entries.is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn relay_v2_rejects_tampered_sequence_body() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let envelope = seal_kv_op(&author, Hlc(10), "k", b"v").to_bytes().unwrap();
        let epoch = [0x44; 32];
        let cursor = RelayCursorV2 { epoch, after: 0 };
        let signed = encoded_relay_response(
            epoch,
            1,
            1,
            vec![RelayWireEntryV2 {
                seq: 1,
                envelope: envelope.clone(),
            }],
        );
        let tampered =
            encoded_relay_response(epoch, 2, 2, vec![RelayWireEntryV2 { seq: 2, envelope }]);
        let client =
            spawn_relay_ops_response(tampered, signed, Arc::clone(&serving), cursor, 10, None)
                .await;

        let error = client
            .fetch_relay_ops_v2(
                &serving,
                serving.device_id(),
                &serving.public_key_sec1(),
                cursor,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn relay_v2_rejects_tampered_envelope_body() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let envelope = seal_kv_op(&author, Hlc(10), "k", b"v").to_bytes().unwrap();
        let mut tampered_envelope = envelope.clone();
        let last = tampered_envelope.last_mut().unwrap();
        *last ^= 0x01;
        let epoch = [0x45; 32];
        let cursor = RelayCursorV2 { epoch, after: 0 };
        let signed =
            encoded_relay_response(epoch, 1, 1, vec![RelayWireEntryV2 { seq: 1, envelope }]);
        let tampered = encoded_relay_response(
            epoch,
            1,
            1,
            vec![RelayWireEntryV2 {
                seq: 1,
                envelope: tampered_envelope,
            }],
        );
        let client =
            spawn_relay_ops_response(tampered, signed, Arc::clone(&serving), cursor, 10, None)
                .await;

        let error = client
            .fetch_relay_ops_v2(
                &serving,
                serving.device_id(),
                &serving.public_key_sec1(),
                cursor,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn relay_v2_rejects_signed_non_monotonic_sequences_before_envelopes() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let envelope = seal_kv_op(&author, Hlc(10), "k", b"v").to_bytes().unwrap();
        let epoch = [0x55; 32];
        let cursor = RelayCursorV2 { epoch, after: 0 };
        let body = encoded_relay_response(
            epoch,
            2,
            1,
            vec![
                RelayWireEntryV2 {
                    seq: 2,
                    envelope: envelope.clone(),
                },
                RelayWireEntryV2 { seq: 1, envelope },
            ],
        );
        let client =
            spawn_relay_ops_response(body.clone(), body, Arc::clone(&serving), cursor, 10, None)
                .await;

        let error = client
            .fetch_relay_ops_v2(
                &serving,
                serving.device_id(),
                &serving.public_key_sec1(),
                cursor,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, TransportError::Wire(message) if message.contains("strictly increasing"))
        );
    }

    #[tokio::test]
    async fn relay_v2_rejects_signed_malformed_envelope() {
        let serving = Arc::new(DeviceIdentity::generate());
        let epoch = [0x66; 32];
        let cursor = RelayCursorV2 { epoch, after: 0 };
        let body = encoded_relay_response(
            epoch,
            1,
            1,
            vec![RelayWireEntryV2 {
                seq: 1,
                envelope: vec![0xff],
            }],
        );
        let client =
            spawn_relay_ops_response(body.clone(), body, Arc::clone(&serving), cursor, 10, None)
                .await;

        let error = client
            .fetch_relay_ops_v2(
                &serving,
                serving.device_id(),
                &serving.public_key_sec1(),
                cursor,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::Op(_)));
    }

    #[tokio::test]
    async fn relay_v2_checks_page_limit_before_decoding_envelopes() {
        let serving = Arc::new(DeviceIdentity::generate());
        let epoch = [0x67; 32];
        let cursor = RelayCursorV2 { epoch, after: 0 };
        let body = encoded_relay_response(
            epoch,
            2,
            2,
            vec![
                RelayWireEntryV2 {
                    seq: 1,
                    envelope: vec![0xff],
                },
                RelayWireEntryV2 {
                    seq: 2,
                    envelope: vec![0xff],
                },
            ],
        );
        let client =
            spawn_relay_ops_response(body.clone(), body, Arc::clone(&serving), cursor, 1, None)
                .await;

        let error = client
            .fetch_relay_ops_v2(
                &serving,
                serving.device_id(),
                &serving.public_key_sec1(),
                cursor,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, TransportError::Wire(message) if message.contains("requested limit"))
        );
    }

    #[tokio::test]
    async fn relay_v2_rejects_signature_from_an_unpinned_key() {
        let serving = DeviceIdentity::generate();
        let attacker = Arc::new(DeviceIdentity::generate());
        let epoch = [0x77; 32];
        let cursor = RelayCursorV2 { epoch, after: 0 };
        let body = encoded_relay_response(epoch, 0, 0, Vec::new());
        let client = spawn_relay_ops_response(body.clone(), body, attacker, cursor, 10, None).await;

        let error = client
            .fetch_relay_ops_v2(
                &serving,
                serving.device_id(),
                &serving.public_key_sec1(),
                cursor,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[test]
    fn relay_v2_rejects_replayed_signature_for_a_different_nonce() {
        let serving = DeviceIdentity::generate();
        let cursor = RelayCursorV2 {
            epoch: [0x88; 32],
            after: 4,
        };
        let body = encoded_relay_response(cursor.epoch, 4, 4, Vec::new());
        let old_nonce = [0x11; 32];
        let next_nonce = [0x22; 32];
        let signature = encode_hex(&sign_relay_response(
            &serving,
            &serving.device_id(),
            RELAY_OPS_SIGNING_CONTEXT,
            &cursor.epoch,
            cursor.after,
            10,
            &old_nonce,
            &body,
        ));

        let error = verify_relay_signature(
            serving.device_id(),
            serving.device_id(),
            &serving.public_key_sec1(),
            RELAY_OPS_SIGNING_CONTEXT,
            cursor,
            10,
            &next_nonce,
            &body,
            &signature,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            TransportError::Identity(crate::error::IdentityError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn relay_v2_unsupported_status_is_reported_precisely() {
        let client = spawn_app(Router::new()).await;
        let expected = DeviceIdentity::generate();

        let error = client
            .fetch_relay_ops_v2(
                &expected,
                expected.device_id(),
                &expected.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap_err();
        assert!(error.is_relay_v2_unsupported());
        assert!(matches!(
            error,
            TransportError::RelayV2Unsupported { status: 404 }
        ));
    }

    #[derive(Clone)]
    struct V1OnlyLog(Arc<Mutex<OpLog>>);

    impl LogSource for V1OnlyLog {
        fn since(&self, cursor: OrderKey, limit: usize) -> Vec<SignedOp> {
            self.0
                .lock()
                .unwrap()
                .since(cursor)
                .take(limit)
                .cloned()
                .collect()
        }

        fn head(&self) -> Option<OrderKey> {
            self.0.lock().unwrap().head()
        }

        fn contains(&self, id: &OpId) -> bool {
            self.0.lock().unwrap().contains(id)
        }
    }

    #[tokio::test]
    async fn v1_only_log_keeps_v1_routes_and_reports_v2_not_implemented() {
        let serving = Arc::new(DeviceIdentity::generate());
        let author = DeviceIdentity::generate();
        let op = seal_kv_op(&author, Hlc(10), "k", b"v");
        let expected_head = op.order_key();
        let log = Arc::new(Mutex::new(OpLog::new()));
        log.lock().unwrap().append(op);
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*author.verifying_key());
        let client = spawn_app(router(ServeState::new(
            Arc::clone(&serving),
            V1OnlyLog(log),
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        assert_eq!(client.fetch_head().await.unwrap(), expected_head);
        let error = client
            .fetch_relay_ops_v2(
                &author,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TransportError::RelayV2Unsupported { status: 501 }
        ));
    }

    #[tokio::test]
    async fn relay_router_does_not_mount_legacy_log_routes() {
        let serving = Arc::new(DeviceIdentity::generate());
        let caller = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*serving.verifying_key());
        registry.insert_key(*caller.verifying_key());
        let client = spawn_app(relay_router(ServeState::new(
            Arc::clone(&serving),
            Arc::new(Mutex::new(OpLog::new())),
            Arc::new(Mutex::new(registry)),
        )))
        .await;

        let legacy = client.fetch_head().await.unwrap_err();
        assert!(
            matches!(legacy, TransportError::Http(message) if message == "status 404 Not Found")
        );
        let relay = client
            .fetch_relay_head_v2(
                &caller,
                serving.device_id(),
                &serving.public_key_sec1(),
                RelayCursorV2::START,
            )
            .await
            .unwrap();
        assert_eq!(relay.head, 0);
    }

    #[tokio::test]
    async fn relay_sync_delivers_a_late_lower_semantic_op() {
        let remote = Arc::new(DeviceIdentity::generate());
        let local = DeviceIdentity::generate();
        let high = seal_kv_op(&remote, Hlc(30), "high", b"first");
        let low = seal_kv_op(&remote, Hlc(10), "low", b"late");
        assert!(low.order_key() < high.order_key());

        let remote_log = Arc::new(Mutex::new(OpLog::new()));
        remote_log.lock().unwrap().append(high.clone());
        let mut remote_registry = DeviceRegistry::new();
        remote_registry.insert_key(*remote.verifying_key());
        remote_registry.insert_key(*local.verifying_key());
        let source = spawn_app(relay_router(ServeState::new(
            Arc::clone(&remote),
            Arc::clone(&remote_log),
            Arc::new(Mutex::new(remote_registry)),
        )))
        .await;

        let mut local_registry = DeviceRegistry::new();
        local_registry.insert_key(*local.verifying_key());
        local_registry.insert_key(*remote.verifying_key());
        let local_registry = Mutex::new(local_registry);
        let clock = NodeClock::new(&local.device_id());
        let local_log = Mutex::new(OpLog::new());
        let store = Mutex::new(KvStore::new());
        let dir = tempfile::tempdir().unwrap();
        let writer = Mutex::new(OplogWriter::open(&dir.path().join("oplog")).unwrap());
        let mut cursor = RelayCursorV2::START;

        let first = sync_relay_once_v2(
            &source,
            &local,
            remote.device_id(),
            &remote.public_key_sec1(),
            &local_registry,
            &clock,
            &local_log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(first.received, 1);
        assert_eq!(first.appended, 1);
        assert_eq!(cursor.after, 1);

        remote_log.lock().unwrap().append(low.clone());
        let late = sync_relay_once_v2(
            &source,
            &local,
            remote.device_id(),
            &remote.public_key_sec1(),
            &local_registry,
            &clock,
            &local_log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap();

        assert_eq!(late.received, 1);
        assert_eq!(late.appended, 1);
        assert_eq!(cursor.after, 2);
        assert!(local_log.lock().unwrap().contains(&high.id));
        assert!(local_log.lock().unwrap().contains(&low.id));
        assert_eq!(store.lock().unwrap().get("high"), Some(&b"first"[..]));
        assert_eq!(store.lock().unwrap().get("low"), Some(&b"late"[..]));
    }

    #[tokio::test]
    async fn relay_sync_authenticates_epoch_reset_and_replays_from_zero() {
        let remote = Arc::new(DeviceIdentity::generate());
        let local = DeviceIdentity::generate();
        let old = seal_kv_op(&remote, Hlc(10), "old", b"one");
        let new = seal_kv_op(&remote, Hlc(20), "new", b"two");

        let first_remote_log = Arc::new(Mutex::new(OpLog::new()));
        first_remote_log.lock().unwrap().append(old.clone());
        let mut first_remote_registry = DeviceRegistry::new();
        first_remote_registry.insert_key(*remote.verifying_key());
        first_remote_registry.insert_key(*local.verifying_key());
        let first_source = spawn_app(relay_router(ServeState::new(
            Arc::clone(&remote),
            first_remote_log,
            Arc::new(Mutex::new(first_remote_registry)),
        )))
        .await;

        let mut local_registry = DeviceRegistry::new();
        local_registry.insert_key(*local.verifying_key());
        local_registry.insert_key(*remote.verifying_key());
        let local_registry = Mutex::new(local_registry);
        let clock = NodeClock::new(&local.device_id());
        let local_log = Mutex::new(OpLog::new());
        let store = Mutex::new(KvStore::new());
        let dir = tempfile::tempdir().unwrap();
        let writer = Mutex::new(OplogWriter::open(&dir.path().join("oplog")).unwrap());
        let mut cursor = RelayCursorV2::START;

        sync_relay_once_v2(
            &first_source,
            &local,
            remote.device_id(),
            &remote.public_key_sec1(),
            &local_registry,
            &clock,
            &local_log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap();
        let first_epoch = cursor.epoch;
        save_relay_cursor(dir.path(), &remote.device_id(), cursor).unwrap();
        let mut cursor = load_relay_cursor(dir.path(), &remote.device_id());

        let restarted_log = Arc::new(Mutex::new(OpLog::new()));
        restarted_log.lock().unwrap().append(old.clone());
        restarted_log.lock().unwrap().append(new.clone());
        let mut restarted_registry = DeviceRegistry::new();
        restarted_registry.insert_key(*remote.verifying_key());
        restarted_registry.insert_key(*local.verifying_key());
        let restarted_source = spawn_app(relay_router(ServeState::new(
            Arc::clone(&remote),
            restarted_log,
            Arc::new(Mutex::new(restarted_registry)),
        )))
        .await;

        let reset = sync_relay_once_v2(
            &restarted_source,
            &local,
            remote.device_id(),
            &remote.public_key_sec1(),
            &local_registry,
            &clock,
            &local_log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap();
        assert!(reset.reset);
        assert_ne!(cursor.epoch, first_epoch);
        assert_eq!(cursor.after, 0);

        let replayed = sync_relay_once_v2(
            &restarted_source,
            &local,
            remote.device_id(),
            &remote.public_key_sec1(),
            &local_registry,
            &clock,
            &local_log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(replayed.received, 2);
        assert_eq!(replayed.appended, 1);
        assert_eq!(cursor.after, 2);
        assert_eq!(local_log.lock().unwrap().len(), 2);
        assert_eq!(store.lock().unwrap().get("old"), Some(&b"one"[..]));
        assert_eq!(store.lock().unwrap().get("new"), Some(&b"two"[..]));
    }

    #[test]
    fn peer_keys_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*a.verifying_key());
        registry.insert_key(*b.verifying_key());
        save_peer_keys(dir.path(), &registry).unwrap();

        let mut restored = DeviceRegistry::new();
        assert_eq!(load_peer_keys(dir.path(), &mut restored), 2);
        assert!(restored.contains(&a.device_id()));
        assert!(restored.contains(&b.device_id()));
        // Missing file loads zero, silently.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(load_peer_keys(empty.path(), &mut DeviceRegistry::new()), 0);
    }

    fn sample_key() -> OrderKey {
        let id = DeviceIdentity::generate();
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: crate::hlc::Hlc(1234),
            device: id.device_id(),
            store: StoreId::new("kv").unwrap(),
            payload: vec![7],
        };
        SignedOp::seal(body, &id).unwrap().order_key()
    }

    #[test]
    fn order_key_hex_round_trips() {
        let key = sample_key();
        let hex = encode_order_key(&key);
        assert_eq!(hex.len(), 144);
        assert_eq!(decode_order_key(&hex), Some(key));
    }

    #[test]
    fn decode_rejects_wrong_length_and_junk() {
        assert_eq!(decode_order_key(""), None);
        assert_eq!(decode_order_key(&"z".repeat(144)), None);
        assert_eq!(decode_order_key(&"0".repeat(143)), None);
    }

    #[test]
    fn min_cursor_encodes_to_all_zero_hex() {
        assert_eq!(encode_order_key(&OrderKey::MIN), "0".repeat(144));
    }

    #[test]
    fn cursor_persistence_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let peer = DeviceIdentity::generate().device_id();
        assert_eq!(load_cursor(dir.path(), &peer), OrderKey::MIN);

        let key = sample_key();
        save_cursor(dir.path(), &peer, key).unwrap();
        assert_eq!(load_cursor(dir.path(), &peer), key);
    }

    #[test]
    fn relay_cursor_persistence_is_versioned_and_independent_from_v1() {
        let dir = tempfile::tempdir().unwrap();
        let peer = DeviceIdentity::generate().device_id();
        let legacy = sample_key();
        save_cursor(dir.path(), &peer, legacy).unwrap();
        assert_eq!(load_relay_cursor(dir.path(), &peer), RelayCursorV2::START);

        let relay = RelayCursorV2 {
            epoch: [0x5a; 32],
            after: 42,
        };
        save_relay_cursor(dir.path(), &peer, relay).unwrap();
        assert_eq!(load_relay_cursor(dir.path(), &peer), relay);
        assert_eq!(load_cursor(dir.path(), &peer), legacy);

        std::fs::write(relay_cursor_path(dir.path(), &peer), [0xff; 7]).unwrap();
        assert_eq!(load_relay_cursor(dir.path(), &peer), RelayCursorV2::START);
    }

    /// A [`PullSource`] that hands back pre-scripted batches, one per `pull`,
    /// ignoring the cursor. Lets a test stage a forged first page and a
    /// legitimate second page.
    struct ScriptedSource {
        batches: Mutex<VecDeque<Vec<SignedOp>>>,
    }

    impl ScriptedSource {
        fn new(batches: Vec<Vec<SignedOp>>) -> Self {
            Self {
                batches: Mutex::new(batches.into_iter().collect()),
            }
        }
    }

    impl PullSource for ScriptedSource {
        type Error = TransportError;

        async fn pull(&self, _since: Cursor) -> Result<Vec<SignedOp>, TransportError> {
            Ok(self.batches.lock().unwrap().pop_front().unwrap_or_default())
        }
    }

    fn seal_kv_op(id: &DeviceIdentity, hlc: Hlc, key: &str, value: &[u8]) -> SignedOp {
        let payload = KvStore::new()
            .encode(&KvOp::Put {
                key: key.to_string(),
                value: value.to_vec(),
            })
            .unwrap();
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc,
            device: id.device_id(),
            store: kv_store_id(),
            payload,
        };
        SignedOp::seal(body, id).unwrap()
    }

    // Regression, finding 1: a forged op with a colossal order key must not
    // poison the durable cursor. The batch aborts, the cursor stays put, and
    // legitimate ops served on a later pull are still applied.
    #[tokio::test]
    async fn forged_high_order_key_op_does_not_poison_cursor() {
        let honest = DeviceIdentity::generate();
        // The forger's key is never registered with the mesh.
        let forger = DeviceIdentity::generate();

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*honest.verifying_key());
        let registry = Mutex::new(registry);
        let clock = NodeClock::new(&honest.device_id());

        // Forged op from an unknown device, stamped with the largest possible
        // HLC so its order key sorts far ahead of every honest op.
        let forged = seal_kv_op(&forger, Hlc(u64::MAX), "evil", b"forged");
        let legit_a = seal_kv_op(&honest, clock.now(), "a", b"from-a");
        let legit_b = seal_kv_op(&honest, clock.now(), "b", b"from-b");

        let source =
            ScriptedSource::new(vec![vec![forged], vec![legit_a.clone(), legit_b.clone()]]);
        let log = Mutex::new(OpLog::new());
        let store = Mutex::new(KvStore::new());
        let mut cursor = OrderKey::MIN;

        // First pull: the forged op is refused and the cursor is not advanced
        // past its huge order key.
        let err = sync_once(&source, &registry, &clock, &log, &store, &mut cursor, None)
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Verify { .. }));
        assert_eq!(cursor, OrderKey::MIN);
        assert_eq!(log.lock().unwrap().len(), 0);

        // Second pull: because the cursor was never poisoned, the legitimate
        // ops are still pulled and applied.
        let n = sync_once(&source, &registry, &clock, &log, &store, &mut cursor, None)
            .await
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(log.lock().unwrap().len(), 2);
        assert_eq!(store.lock().unwrap().get("a"), Some(&b"from-a"[..]));
        assert_eq!(store.lock().unwrap().get("b"), Some(&b"from-b"[..]));
    }

    // Regression, codex phase-1 round 2: a failed durable append must not
    // leave a memory-only op behind. Durable-first ordering means the op is
    // absent from BOTH logs after the failure, so the retry re-pulls it as
    // new (not as a verified duplicate that would advance the cursor past an
    // op the durable file never received).
    #[tokio::test]
    async fn failed_durable_append_leaves_no_memory_only_op() {
        let honest = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*honest.verifying_key());
        let clock = NodeClock::new(&honest.device_id());

        let registry = Mutex::new(registry);
        let op = seal_kv_op(&honest, clock.now(), "k", b"v");
        let source = ScriptedSource::new(vec![vec![op.clone()], vec![op.clone()]]);

        let dir = tempfile::tempdir().unwrap();
        let oplog_path = dir.path().join("oplog");
        let writer = Mutex::new(OplogWriter::open(&oplog_path).unwrap());
        writer.lock().unwrap().fail_next_append();

        let log = Mutex::new(OpLog::new());
        let store = Mutex::new(KvStore::new());
        let mut cursor = OrderKey::MIN;

        // First pull: durable append fails; the op must be in NEITHER log and
        // the cursor must not move.
        let err = sync_once(
            &source,
            &registry,
            &clock,
            &log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TransportError::Durability(_)));
        assert_eq!(cursor, OrderKey::MIN);
        assert_eq!(log.lock().unwrap().len(), 0);

        // Retry: the op is re-pulled as new, lands durably and in memory, and
        // the cursor advances only now.
        let n = sync_once(
            &source,
            &registry,
            &clock,
            &log,
            &store,
            &mut cursor,
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(cursor, op.order_key());
        assert_eq!(store.lock().unwrap().get("k"), Some(&b"v"[..]));
        // The durable file holds exactly the op the memory log holds.
        let mut recovered = OpLog::new();
        let restored = crate::durable::replay_oplog_file(
            &oplog_path,
            &registry.lock().unwrap(),
            &mut recovered,
        )
        .unwrap();
        assert_eq!(restored, 1);
    }

    // Regression, finding 2: an op whose HLC is far beyond the drift bound is
    // rejected before it can enter the log — the guard is enforced, not
    // advisory — and it never reaches the store or moves the cursor.
    #[tokio::test]
    async fn op_beyond_drift_bound_is_rejected_and_absent() {
        let honest = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*honest.verifying_key());
        let registry = Mutex::new(registry);
        let clock = NodeClock::new(&honest.device_id());

        // Signature is valid (the device is known) but the HLC is ~2106,
        // centuries past physical time and well beyond the 1h drift guard.
        let drifted = seal_kv_op(&honest, Hlc(u64::MAX), "x", b"way-ahead");

        let source = ScriptedSource::new(vec![vec![drifted]]);
        let log = Mutex::new(OpLog::new());
        let store = Mutex::new(KvStore::new());
        let mut cursor = OrderKey::MIN;

        let err = sync_once(&source, &registry, &clock, &log, &store, &mut cursor, None)
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Drift { .. }));
        assert_eq!(cursor, OrderKey::MIN);
        assert!(log.lock().unwrap().is_empty());
        assert!(store.lock().unwrap().is_empty());
    }

    /// A store that counts every `apply` call, to prove incremental mode touches
    /// only newly-crossed ops rather than re-walking the whole log each pull.
    #[derive(Default)]
    struct CountingStore {
        applies: usize,
        data: std::collections::BTreeMap<String, Vec<u8>>,
    }

    impl Store for CountingStore {
        type Op = KvOp;
        type Error = crate::kv::KvError;

        fn store_id(&self) -> StoreId {
            kv_store_id()
        }

        fn encode(&self, op: &KvOp) -> Result<Vec<u8>, Self::Error> {
            Ok(postcard::to_allocvec(op)?)
        }

        fn decode(&self, payload: &[u8]) -> Result<KvOp, Self::Error> {
            Ok(postcard::from_bytes(payload)?)
        }

        fn apply(
            &mut self,
            _ctx: crate::store::OpContext<'_>,
            op: KvOp,
        ) -> Result<(), Self::Error> {
            self.applies += 1;
            if let KvOp::Put { key, value } = op {
                self.data.insert(key, value);
            }
            Ok(())
        }
    }

    // G1: incremental apply calls `Store::apply` once per newly-crossed op, not
    // once per op in the whole log. Three ops then one more must be exactly four
    // applies (whole-log replay would be 3 + 4 = 7).
    #[tokio::test]
    async fn incremental_apply_only_touches_new_ops() {
        let honest = DeviceIdentity::generate();
        let mut registry = DeviceRegistry::new();
        registry.insert_key(*honest.verifying_key());
        let registry = Mutex::new(registry);
        let clock = NodeClock::new(&honest.device_id());

        let op1 = seal_kv_op(&honest, clock.now(), "a", b"1");
        let op2 = seal_kv_op(&honest, clock.now(), "b", b"2");
        let op3 = seal_kv_op(&honest, clock.now(), "c", b"3");
        let op4 = seal_kv_op(&honest, clock.now(), "d", b"4");
        let source = ScriptedSource::new(vec![
            vec![op1.clone(), op2.clone(), op3.clone()],
            vec![op4.clone()],
        ]);

        let log = Mutex::new(OpLog::new());
        let store = Mutex::new(CountingStore::default());
        let mut cursor = OrderKey::MIN;

        let n = sync_once_with(
            &source,
            &registry,
            &clock,
            &log,
            &store,
            &mut cursor,
            None,
            ApplyMode::Incremental,
        )
        .await
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(store.lock().unwrap().applies, 3);

        let n = sync_once_with(
            &source,
            &registry,
            &clock,
            &log,
            &store,
            &mut cursor,
            None,
            ApplyMode::Incremental,
        )
        .await
        .unwrap();
        assert_eq!(n, 1);
        // 3 from the first batch + 1 from the second, never re-applying history.
        assert_eq!(store.lock().unwrap().applies, 4);
        assert_eq!(store.lock().unwrap().data.get("d"), Some(&b"4".to_vec()));
    }

    // ---- push-delivery (`/watch`) ----------------------------------------

    /// Spawn a loopback node serving the full router with a wired
    /// [`HeadPublisher`] and a `watch_limit`-capped `/watch`, returning the base
    /// URL (so a test can open several clients against it), the shared log, and
    /// the publisher so a test can append + signal a head change.
    async fn spawn_watch_node_with_limit(
        watch_limit: usize,
    ) -> (String, Arc<Mutex<OpLog>>, HeadPublisher) {
        let identity = Arc::new(DeviceIdentity::generate());
        let log = Arc::new(Mutex::new(OpLog::new()));
        let mut reg = DeviceRegistry::new();
        reg.insert_key(*identity.verifying_key());
        let devices = Arc::new(Mutex::new(reg));

        let head = HeadPublisher::new(OrderKey::MIN);
        let state = ServeState::new(identity, log.clone(), devices)
            .with_watch(head.watch())
            .with_watch_limit(watch_limit);
        let app = router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), log, head)
    }

    /// The common case: a node with the default parked-watch cap, returning a
    /// single client.
    async fn spawn_watch_node() -> (HttpPullSource, Arc<Mutex<OpLog>>, HeadPublisher) {
        let (base, log, head) = spawn_watch_node_with_limit(DEFAULT_MAX_PARKED_WATCHES).await;
        (HttpPullSource::new(base), log, head)
    }

    // A parked `/watch` must return within milliseconds of an append+publish,
    // not at the hold deadline — the whole point of push delivery.
    #[tokio::test]
    async fn watch_returns_promptly_after_append() {
        let (client, log, head) = spawn_watch_node().await;
        let author = DeviceIdentity::generate();

        let appender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let op = seal_kv_op(&author, Hlc(1_000), "k", b"v");
            let new_head = op.order_key();
            log.lock().unwrap().append(op);
            head.publish(new_head);
        });

        let start = Instant::now();
        let observed = client
            .watch_head(OrderKey::MIN, Duration::from_secs(10))
            .await
            .unwrap();
        let elapsed = start.elapsed();
        appender.await.unwrap();

        assert_ne!(observed, OrderKey::MIN, "watch returned the unchanged head");
        assert!(
            elapsed < Duration::from_secs(2),
            "watch parked to the deadline instead of waking on the append: {elapsed:?}"
        );
    }

    // With no append, `/watch` holds for `wait` and then returns the unchanged
    // head cleanly (a 200, not an error), so the client re-arms without a stall.
    #[tokio::test]
    async fn watch_times_out_cleanly_at_the_deadline() {
        let (client, _log, _head) = spawn_watch_node().await;
        let start = Instant::now();
        let observed = client
            .watch_head(OrderKey::MIN, Duration::from_millis(300))
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(observed, OrderKey::MIN);
        assert!(
            elapsed >= Duration::from_millis(250),
            "watch returned before its hold window: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "watch overran its hold window: {elapsed:?}"
        );
    }

    // An old peer without `/watch` answers 404; `watch_head` surfaces that as an
    // Err so the pull loop degrades to interval polling on that link.
    #[tokio::test]
    async fn watch_head_errs_against_router_without_watch() {
        // A bare router with no `/watch` route stands in for a pre-push peer.
        let app: Router = Router::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = HttpPullSource::new(format!("http://{addr}"));
        let err = client
            .watch_head(OrderKey::MIN, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Http(_)), "got {err:?}");
    }

    // Regression, finding 1: a cursor that sorts strictly AHEAD of the peer's
    // head must not return immediately (the old `head != known` test that spun a
    // tight watch/empty-pull loop). It parks the whole window and then reports
    // the peer's actual — behind — head.
    #[tokio::test]
    async fn watch_parks_when_cursor_is_ahead_of_head() {
        let (base, log, _head) = spawn_watch_node_with_limit(DEFAULT_MAX_PARKED_WATCHES).await;
        let client = HttpPullSource::new(base);
        let author = DeviceIdentity::generate();

        // Give the node a real, non-MIN head.
        let low = seal_kv_op(&author, Hlc(1_000), "k", b"v");
        let head_key = low.order_key();
        log.lock().unwrap().append(low);

        // A cursor carrying a far-future HLC sorts strictly ahead of that head.
        let ahead = seal_kv_op(&author, Hlc(u64::MAX), "future", b"x").order_key();
        assert!(ahead > head_key, "test cursor must sort ahead of the head");

        let start = Instant::now();
        let observed = client
            .watch_head(ahead, Duration::from_millis(300))
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(250),
            "watch returned early instead of parking on an ahead-cursor: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "watch overran its hold window: {elapsed:?}"
        );
        // It reports the true head, which is behind the caller's cursor.
        assert_eq!(observed, head_key);
    }

    // Finding 3: `/watch` admission control. With the cap set to 1, the first
    // watch parks and holds the only permit; a second concurrent watch is over
    // capacity and must return immediately with the head (degrade to polling)
    // rather than park.
    #[tokio::test]
    async fn watch_admission_cap_returns_immediately_over_capacity() {
        let (base, _log, _head) = spawn_watch_node_with_limit(1).await;

        // First watch parks for the full window, holding the single permit.
        let hold_base = base.clone();
        let parked = tokio::spawn(async move {
            HttpPullSource::new(hold_base)
                .watch_head(OrderKey::MIN, Duration::from_secs(3))
                .await
        });
        // Let the parked watch reach the server and acquire the permit.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Second watch: over the cap, must not park.
        let start = Instant::now();
        let observed = HttpPullSource::new(base)
            .watch_head(OrderKey::MIN, Duration::from_secs(3))
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            observed,
            OrderKey::MIN,
            "over-cap watch should echo the head"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "over-cap watch parked instead of degrading to an immediate head: {elapsed:?}"
        );

        // The first watch is still parked; let it time out cleanly.
        let _ = parked.await.unwrap();
    }

    // Finding (this changeset): an over-capacity `/watch` answers Ok immediately
    // with an unchanged head. A consumer that re-arms on any Ok spins a tight
    // watch/empty-pull loop under saturation. The client contract is to treat an
    // unchanged head (head <= cursor) like a timeout and sleep WATCH_EMPTY_BACKOFF
    // before re-arming. A zero-capacity server forces the immediate-echo path every
    // time; over a fixed window the honored backoff must bound the re-arm count to a
    // small multiple of window/backoff, not the hundreds a busy loop would reach.
    #[tokio::test]
    async fn unchanged_head_watch_does_not_busy_loop() {
        // Cap of 0: every `/watch` is over capacity, so the server sheds the park
        // and echoes the current head (MIN) with no hold — the saturation case.
        let (base, _log, _head) = spawn_watch_node_with_limit(0).await;
        let client = HttpPullSource::new(base);
        let cursor = OrderKey::MIN;

        let window = Duration::from_millis(1_200);
        let deadline = Instant::now() + window;
        let mut calls = 0usize;
        while Instant::now() < deadline {
            let head = client
                .watch_head(cursor, Duration::from_secs(5))
                .await
                .unwrap();
            calls += 1;
            // The consumer fix: an Ok carrying no new head backs off instead of
            // re-arming instantly.
            if head <= cursor {
                tokio::time::sleep(WATCH_EMPTY_BACKOFF).await;
            }
        }

        // With the backoff honored, calls ≈ window / WATCH_EMPTY_BACKOFF (+1); a
        // busy loop would reach into the hundreds. The ceiling is generous so the
        // assertion keys on "bounded, not spinning," not an exact count.
        let ceiling = (window.as_millis() / WATCH_EMPTY_BACKOFF.as_millis()) as usize + 3;
        assert!(
            calls <= ceiling,
            "unchanged-head watch re-armed {calls} times in {window:?} (ceiling {ceiling}); \
             it is busy-looping instead of backing off WATCH_EMPTY_BACKOFF"
        );
    }
}
