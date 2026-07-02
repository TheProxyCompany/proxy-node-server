//! In-process multi-daemon harness (feature `harness`) shared by the functional
//! convergence tests and the timing examples. Boots N nodes on loopback, each
//! serving its op-log over the real HTTP transport, and drives them through the
//! whole seal → serve → pull → verify → apply path. Not compiled into default
//! builds; carries no assertions of its own (the tests own pass/fail).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::kv::{KvOp, KvStore, kv_store_id};
use crate::{
    DeviceIdentity, DeviceRegistry, ENVELOPE_VERSION, HttpPullSource, NodeClock, OpBody, OpId,
    OpLog, OrderKey, ServeState, SignedOp, Store, learn_devices, register_peer, replay, router,
    sync_once,
};

/// One in-process node: identity, clock, shared log, store, a device registry it
/// both verifies against and gossips over `/devices`, and a loopback server.
pub struct MeshNode {
    pub identity: Arc<DeviceIdentity>,
    pub clock: NodeClock,
    pub log: Arc<Mutex<OpLog>>,
    pub store: Mutex<KvStore>,
    pub registry: Arc<Mutex<DeviceRegistry>>,
    pub base_url: String,
}

impl MeshNode {
    /// Bind a loopback server on an ephemeral port and start serving.
    pub async fn spawn() -> MeshNode {
        Self::spawn_on(([127, 0, 0, 1], 0).into()).await
    }

    /// Bind `addr` and start serving this node's log + device book. `spawn` is
    /// the loopback-ephemeral case for the in-process tests; the multi-machine
    /// mesh benchmark binds a real, externally reachable address (e.g.
    /// `0.0.0.0:51713`). `base_url` reflects the address actually bound.
    pub async fn spawn_on(addr: std::net::SocketAddr) -> MeshNode {
        let identity = Arc::new(DeviceIdentity::generate());
        let clock = NodeClock::new(&identity.device_id());
        let log = Arc::new(Mutex::new(OpLog::new()));
        let store = Mutex::new(KvStore::new());

        let mut reg = DeviceRegistry::new();
        reg.insert_key(*identity.verifying_key());
        let registry = Arc::new(Mutex::new(reg));

        let app = router(ServeState::new(
            identity.clone(),
            log.clone(),
            registry.clone(),
        ));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        MeshNode {
            identity,
            clock,
            log,
            store,
            registry,
            base_url: format!("http://{bound}"),
        }
    }

    /// Seal a local op, append it, and replay the store.
    pub fn commit(&self, op: &KvOp) -> OpId {
        let payload = KvStore::new().encode(op).unwrap();
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: self.clock.now(),
            device: self.identity.device_id(),
            store: kv_store_id(),
            payload,
        };
        let signed = SignedOp::seal(body, &self.identity).unwrap();
        let id = signed.id;
        {
            let mut log = self.log.lock().unwrap();
            log.append(signed);
        }
        let log = self.log.lock().unwrap();
        let mut store = self.store.lock().unwrap();
        replay(&log, &mut *store).unwrap();
        id
    }

    /// Register `peer`, learn every device it vouches for (transitive keys), and
    /// pull it to exhaustion over HTTP.
    pub async fn sync_from(&self, peer: &MeshNode) {
        let source = HttpPullSource::new(&peer.base_url);
        register_peer(&source, &self.registry).await.unwrap();
        // Learn keys for devices this node has not met directly, so ops the peer
        // relays from third parties verify instead of aborting the batch.
        learn_devices(&source, &self.registry).await.unwrap();

        let mut cursor = OrderKey::MIN;
        loop {
            let n = sync_once(
                &source,
                &self.registry,
                &self.clock,
                &self.log,
                &self.store,
                &mut cursor,
                None,
            )
            .await
            .unwrap();
            if n == 0 {
                break;
            }
        }
    }

    pub fn head(&self) -> Option<OrderKey> {
        self.log.lock().unwrap().head()
    }

    pub fn log_len(&self) -> usize {
        self.log.lock().unwrap().len()
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.store.lock().unwrap().get(key).map(<[u8]>::to_vec)
    }
}

/// Spawn `n` loopback mesh nodes.
pub async fn spawn_mesh(n: usize) -> Vec<MeshNode> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(MeshNode::spawn().await);
    }
    nodes
}

/// Full-mesh pull rounds until every node's head matches, or `max_rounds` is
/// hit. Returns the number of rounds it took (`max_rounds` if it never settled).
pub async fn converge(nodes: &[MeshNode], max_rounds: usize) -> usize {
    for round in 1..=max_rounds {
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    nodes[i].sync_from(&nodes[j]).await;
                }
            }
        }
        if heads_equal(nodes) {
            return round;
        }
    }
    max_rounds
}

/// Whether every node holds the same log head.
pub fn heads_equal(nodes: &[MeshNode]) -> bool {
    let mut heads = nodes.iter().map(MeshNode::head);
    match heads.next() {
        Some(first) => heads.all(|h| h == first),
        None => true,
    }
}

/// Build an op-log plus its verifying registry pre-seeded with `n` sealed ops
/// from one device, for the daemon-startup / replay-cost bench.
pub fn seeded_log(n: usize) -> (OpLog, DeviceRegistry) {
    let id = DeviceIdentity::generate();
    let clock = NodeClock::new(&id.device_id());
    let template = KvStore::new();
    let mut log = OpLog::new();
    for i in 0..n {
        let payload = template
            .encode(&KvOp::Put {
                key: format!("k{i}"),
                value: (i as u64).to_le_bytes().to_vec(),
            })
            .unwrap();
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: clock.now(),
            device: id.device_id(),
            store: kv_store_id(),
            payload,
        };
        log.append(SignedOp::seal(body, &id).unwrap());
    }
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*id.verifying_key());
    (log, registry)
}

/// Resident set size of a process in KiB, via `ps` (macOS + Linux), for the
/// memory-over-time bench. `None` if `ps` is unavailable or the pid is gone.
pub fn rss_kib(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Elapsed wall time running `f` to completion, a convenience for the timing
/// scripts.
pub fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}
