//! HTTP pull transport (feature `pull-http`): the server routes a node exposes,
//! the [`HttpPullSource`] client that pulls a peer's ops, and [`sync_once`], the
//! one-shot pull step the daemon loops over. All bodies are postcard over
//! `application/octet-stream`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};

use crate::durable::OplogWriter;
use crate::error::TransportError;
use crate::hlc::NodeClock;
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::{OpLog, replay};
use crate::op::{OrderKey, SignedOp};
use crate::registry::DeviceRegistry;
use crate::store::Store;
use crate::transport::{Cursor, PullSource};

/// Default cap on the number of ops returned by one `/ops` page.
pub const DEFAULT_PULL_LIMIT: u16 = 512;

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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Shared state the pull routes serve from: this node's identity and its log.
/// The log is the same handle the pull loop appends into.
#[derive(Clone)]
pub struct ServeState {
    identity: Arc<DeviceIdentity>,
    log: Arc<Mutex<OpLog>>,
}

impl ServeState {
    pub fn new(identity: Arc<DeviceIdentity>, log: Arc<Mutex<OpLog>>) -> Self {
        Self { identity, log }
    }
}

/// Build the `/identity`, `/ops`, and `/head` router for a node.
pub fn router(state: ServeState) -> Router {
    Router::new()
        .route("/identity", get(get_identity))
        .route("/ops", get(get_ops))
        .route("/head", get(get_head))
        .with_state(state)
}

fn octet(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

async fn get_identity(State(state): State<ServeState>) -> Response {
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

async fn get_ops(State(state): State<ServeState>, Query(q): Query<OpsQuery>) -> Response {
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
    {
        let log = state.log.lock().expect("oplog mutex poisoned");
        for op in log.since(cursor).take(limit) {
            match op.to_bytes() {
                Ok(bytes) => {
                    ops.push(bytes);
                    next = op.order_key();
                }
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
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

async fn get_head(State(state): State<ServeState>) -> Response {
    let head = state
        .log
        .lock()
        .expect("oplog mutex poisoned")
        .head()
        .unwrap_or(OrderKey::MIN);
    octet(head.to_wire().to_vec())
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
            client: reqwest::Client::new(),
            limit: DEFAULT_PULL_LIMIT,
        }
    }

    pub fn with_limit(mut self, limit: u16) -> Self {
        self.limit = limit;
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
    registry: &mut DeviceRegistry,
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
    let newly_added = !registry.contains(&advertised);
    registry.insert_sec1(&sec1)?;
    Ok((advertised, newly_added))
}

/// One incremental pull from `source`. Each returned op is verified against the
/// device registry (a peer serves ops from several devices, including the
/// puller's own echoed back), its HLC folded into the local clock, and new ops
/// appended — persisted when `durability` is set. The store is then replayed.
///
/// `cursor` only advances over ops that were actually verified and applied (or
/// verified and skipped as genuine duplicates). The first op that fails
/// verification or the drift guard aborts the batch: the cursor is left at the
/// last verified op and a [`TransportError`] naming the offending device is
/// returned, so a forged op with a huge order key can never poison the durable
/// cursor and skip later legitimate ops. Returns the number of newly appended
/// ops on success.
#[allow(clippy::too_many_arguments)]
pub async fn sync_once<S, P>(
    source: &P,
    registry: &DeviceRegistry,
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
    let ops = source.pull(*cursor).await?;
    let mut appended = 0;
    let mut highest = *cursor;
    // The first op that fails a check aborts the batch. Ops before it are fully
    // verified-and-applied (or verified genuine duplicates), so the cursor may
    // advance over them; the offending op and everything after it are not
    // reached, so the cursor never moves past the failure point.
    let mut abort: Option<TransportError> = None;
    {
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
    // Replay whenever the cursor moves, not only when this batch appended:
    // after a failed fsync, the retry sees the batch's ops as verified
    // duplicates (appended == 0) yet still advances the cursor, and the store
    // must not be left behind the log at that point. Replay is idempotent
    // whole-log application, so re-running it over duplicates is safe.
    if highest != *cursor {
        let log = log.lock().expect("oplog mutex poisoned");
        let mut store = store.lock().expect("store mutex poisoned");
        replay(&log, &mut *store).map_err(|e| TransportError::Replay(e.to_string()))?;
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
        let restored =
            crate::durable::replay_oplog_file(&oplog_path, &registry, &mut recovered).unwrap();
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
}
