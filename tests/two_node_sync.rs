//! Two-daemon end-to-end convergence over the HTTP pull transport (D2.7).
//! Each node binds a real `/identity`+`/ops`+`/head` server on a loopback port
//! and pulls the other over HTTP, exercising the whole path: seal → serve →
//! pull → verify → fold → append → durable → replay.
#![cfg(feature = "pull-http")]

use std::sync::{Arc, Mutex};

use proxy_node_server::kv::kv_store_id;
use proxy_node_server::{
    DeviceIdentity, DeviceRegistry, ENVELOPE_VERSION, HttpPullSource, KvOp, KvStore, NodeClock,
    OpBody, OpId, OpLog, OplogWriter, OrderKey, ServeState, SignedOp, Store, register_peer, replay,
    router, sync_once,
};

/// One in-process node: identity, clock, shared log, store, durable file, and a
/// loopback server serving that log.
struct Node {
    identity: Arc<DeviceIdentity>,
    clock: NodeClock,
    log: Arc<Mutex<OpLog>>,
    store: Mutex<KvStore>,
    writer: Mutex<OplogWriter>,
    base_url: String,
    _dir: tempfile::TempDir,
}

impl Node {
    async fn spawn() -> Node {
        let dir = tempfile::tempdir().unwrap();
        let identity = Arc::new(DeviceIdentity::generate());
        let clock = NodeClock::new(&identity.device_id());
        let log = Arc::new(Mutex::new(OpLog::new()));
        let store = Mutex::new(KvStore::new());
        let writer = Mutex::new(OplogWriter::open(&dir.path().join("oplog.bin")).unwrap());

        let app = router(ServeState::new(identity.clone(), log.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Node {
            identity,
            clock,
            log,
            store,
            writer,
            base_url: format!("http://{addr}"),
            _dir: dir,
        }
    }

    /// Seal a local op, append it, persist it, and replay the store.
    fn commit(&self, op: &KvOp) -> OpId {
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
            if log.append(signed.clone()) {
                self.writer.lock().unwrap().append(&signed).unwrap();
            }
        }
        self.replay_store();
        id
    }

    fn replay_store(&self) {
        let log = self.log.lock().unwrap();
        let mut store = self.store.lock().unwrap();
        replay(&log, &mut *store).unwrap();
    }

    /// Pull `peer` to exhaustion via the HTTP transport.
    async fn sync_from(&self, peer: &Node) {
        let source = HttpPullSource::new(&peer.base_url);
        let mut registry = DeviceRegistry::new();
        // A peer serves ops from several devices, including ours echoed back, so
        // both keys must be resolvable.
        registry.insert_key(*self.identity.verifying_key());
        let (advertised, newly_added) = register_peer(&source, &mut registry).await.unwrap();
        assert_eq!(advertised, peer.identity.device_id());
        assert!(newly_added);

        let mut cursor = OrderKey::MIN;
        loop {
            let n = sync_once(
                &source,
                &registry,
                &self.clock,
                &self.log,
                &self.store,
                &mut cursor,
                Some(&self.writer),
            )
            .await
            .unwrap();
            if n == 0 {
                break;
            }
        }
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.store.lock().unwrap().get(key).map(<[u8]>::to_vec)
    }

    fn log_len(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

#[tokio::test]
async fn two_nodes_converge_both_ways() {
    let a = Node::spawn().await;
    let b = Node::spawn().await;

    a.commit(&KvOp::Put {
        key: "a".into(),
        value: b"from-a".to_vec(),
    });
    b.commit(&KvOp::Put {
        key: "b".into(),
        value: b"from-b".to_vec(),
    });

    a.sync_from(&b).await;
    b.sync_from(&a).await;

    // Both logs hold both ops, and both stores agree on every key.
    assert_eq!(a.log_len(), 2);
    assert_eq!(b.log_len(), 2);
    assert_eq!(a.get("a"), Some(b"from-a".to_vec()));
    assert_eq!(a.get("b"), Some(b"from-b".to_vec()));
    assert_eq!(b.get("a"), Some(b"from-a".to_vec()));
    assert_eq!(b.get("b"), Some(b"from-b".to_vec()));

    // Idempotency: another full round appends nothing and leaves state stable.
    a.sync_from(&b).await;
    b.sync_from(&a).await;
    assert_eq!(a.log_len(), 2);
    assert_eq!(b.log_len(), 2);
}

#[tokio::test]
async fn concurrent_writes_resolve_identically() {
    let a = Node::spawn().await;
    let b = Node::spawn().await;

    // Both write the same key at overlapping wall time.
    a.commit(&KvOp::Put {
        key: "x".into(),
        value: b"x-from-a".to_vec(),
    });
    b.commit(&KvOp::Put {
        key: "x".into(),
        value: b"x-from-b".to_vec(),
    });

    a.sync_from(&b).await;
    b.sync_from(&a).await;

    // LWW resolved identically by the (hlc, device, op_id) total order.
    assert_eq!(a.get("x"), b.get("x"));
    let winner = a.get("x").unwrap();
    assert!(winner == b"x-from-a".to_vec() || winner == b"x-from-b".to_vec());
    assert_eq!(a.log_len(), 2);
    assert_eq!(b.log_len(), 2);
}
