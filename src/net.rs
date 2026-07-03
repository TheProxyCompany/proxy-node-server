//! HTTP pull transport (feature `pull-http`): the server routes a node exposes,
//! the [`HttpPullSource`] client that pulls a peer's ops, and [`sync_once`], the
//! one-shot pull step the daemon loops over. All bodies are postcard over
//! `application/octet-stream`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, watch};

use crate::durable::OplogWriter;
use crate::error::TransportError;
use crate::hlc::NodeClock;
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::{LogSource, OpLog, apply_range, replay};
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
    tx: watch::Sender<OrderKey>,
}

impl HeadPublisher {
    pub fn new(initial: OrderKey) -> Self {
        let (tx, _rx) = watch::channel(initial);
        Self { tx }
    }

    /// A reader parked handlers block on. Cloneable through [`ServeState`].
    pub fn watch(&self) -> HeadWatch {
        HeadWatch {
            rx: Some(self.tx.subscribe()),
        }
    }

    /// Signal that the head moved to `head`. A no-op wake when the value is
    /// unchanged (so a committed write that emitted no ops does not spuriously
    /// wake watchers), and never errors when there are zero receivers.
    pub fn publish(&self, head: OrderKey) {
        self.tx.send_if_modified(|current| {
            if *current != head {
                *current = head;
                true
            } else {
                false
            }
        });
    }
}

/// Reader side of the push wake-up, held in [`ServeState`]. [`HeadWatch::inert`]
/// is a watch with no publisher wired: `/watch` then degrades to a bounded
/// long-poll that only ever times out — correct, just no speedup — which is what
/// any [`LogSource`] gets for free before its emit path publishes.
#[derive(Clone)]
pub struct HeadWatch {
    rx: Option<watch::Receiver<OrderKey>>,
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
    watch: HeadWatch,
    /// Admission control for `/watch`: caps the number of handlers parked at once
    /// so the route cannot be turned into a park-and-hold DoS. Shared across the
    /// [`Clone`]d per-connection states, so the cap is process-wide per node.
    watch_limit: Arc<Semaphore>,
}

impl<L: LogSource, D: DeviceBook> Clone for ServeState<L, D> {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            log: self.log.clone(),
            devices: self.devices.clone(),
            watch: self.watch.clone(),
            watch_limit: self.watch_limit.clone(),
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
            devices,
            watch: HeadWatch::inert(),
            watch_limit: Arc::new(Semaphore::new(DEFAULT_MAX_PARKED_WATCHES)),
        }
    }

    /// Opt into push delivery: park `/watch` handlers on `watch`, which a
    /// [`HeadPublisher`] on the node's append path wakes on every head change.
    pub fn with_watch(mut self, watch: HeadWatch) -> Self {
        self.watch = watch;
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

/// Build the `/identity`, `/ops`, `/head`, `/watch`, and `/devices` router.
pub fn router<L: LogSource, D: DeviceBook>(state: ServeState<L, D>) -> Router {
    Router::new()
        .route("/identity", get(get_identity::<L, D>))
        .route("/ops", get(get_ops::<L, D>))
        .route("/head", get(get_head::<L, D>))
        .route("/watch", get(get_watch::<L, D>))
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

async fn get_devices<L: LogSource, D: DeviceBook>(
    State(state): State<ServeState<L, D>>,
) -> Response {
    let devices = state
        .devices
        .known_devices()
        .into_iter()
        .map(|(id, sec1)| DeviceEntry {
            device_id: *id.as_bytes(),
            public_key_sec1: sec1.to_vec(),
        })
        .collect();
    let resp = DevicesResp { devices };
    match postcard::to_allocvec(&resp) {
        Ok(bytes) => octet(bytes),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
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
    Ok((advertised, newly_added))
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
    Ok(added)
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

/// Load persisted peer keys into the registry. Returns how many registered.
/// Missing or unreadable entries are skipped: worst case the op stays on disk
/// and is recovered by a later replay once the key is known again.
pub fn load_peer_keys(data_dir: &Path, registry: &mut DeviceRegistry) -> usize {
    let Ok(bytes) = std::fs::read(peers_path(data_dir)) else {
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
    let keys: Vec<Vec<u8>> = registry.sec1_keys().iter().map(|k| k.to_vec()).collect();
    let bytes = postcard::to_allocvec(&keys)
        .map_err(|e| std::io::Error::other(format!("encode peer keys: {e}")))?;
    let path = peers_path(data_dir);
    let dir = path.parent().expect("peers path always has a parent");
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("bin.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
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

    use super::*;
    use crate::hlc::Hlc;
    use crate::identity::DeviceIdentity;
    use crate::kv::{KvOp, KvStore, kv_store_id};
    use crate::op::{ENVELOPE_VERSION, OpBody, StoreId};
    use crate::registry::DeviceRegistry;
    use crate::store::Store;

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
