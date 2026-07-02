//! In-process two-node convergence, using only the always-available primitives
//! (no `pull-http`). A "pull" is `OpLog::since` over the peer's log; each op is
//! verified against the device registry, its HLC folded, and appended — the same
//! sequence the HTTP transport performs, minus the wire. Proves the ordering and
//! LWW-convergence contract without binding a socket.

use proxy_node_server::kv::kv_store_id;
use proxy_node_server::{
    DeviceIdentity, DeviceRegistry, ENVELOPE_VERSION, KvOp, KvStore, NodeClock, OpBody, OpLog,
    OrderKey, SignedOp, Store, replay,
};

struct Node {
    identity: DeviceIdentity,
    clock: NodeClock,
    log: OpLog,
    store: KvStore,
}

impl Node {
    fn new() -> Node {
        let identity = DeviceIdentity::generate();
        let clock = NodeClock::new(&identity.device_id());
        Node {
            identity,
            clock,
            log: OpLog::new(),
            store: KvStore::new(),
        }
    }

    fn commit(&mut self, op: &KvOp) {
        let payload = self.store.encode(op).unwrap();
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: self.clock.now(),
            device: self.identity.device_id(),
            store: kv_store_id(),
            payload,
        };
        let signed = SignedOp::seal(body, &self.identity).unwrap();
        self.log.append(signed);
        replay(&self.log, &mut self.store).unwrap();
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.store.get(key).map(<[u8]>::to_vec)
    }
}

/// Pull every op after `cursor` from `peer_log` into `local`, verifying each
/// against `registry`. Returns the resume cursor.
fn pull(
    local: &mut Node,
    peer_log: &OpLog,
    cursor: OrderKey,
    registry: &DeviceRegistry,
) -> OrderKey {
    let mut highest = cursor;
    for op in peer_log.since(cursor) {
        if op.order_key() > highest {
            highest = op.order_key();
        }
        let Some(key) = registry.key_for(&op.body.device) else {
            continue;
        };
        if op.verify(key).is_err() {
            continue;
        }
        let _ = local.clock.update(op.body.hlc, &op.body.device);
        local.log.append(op.clone());
    }
    replay(&local.log, &mut local.store).unwrap();
    highest
}

fn registry_of(nodes: &[&Node]) -> DeviceRegistry {
    let mut reg = DeviceRegistry::new();
    for n in nodes {
        reg.insert_key(*n.identity.verifying_key());
    }
    reg
}

#[test]
fn two_nodes_converge_and_are_idempotent() {
    let mut a = Node::new();
    let mut b = Node::new();

    a.commit(&KvOp::Put {
        key: "a".into(),
        value: b"from-a".to_vec(),
    });
    b.commit(&KvOp::Put {
        key: "b".into(),
        value: b"from-b".to_vec(),
    });

    let reg = registry_of(&[&a, &b]);

    // Snapshot each peer's log before cross-applying, so neither pull observes
    // the other's freshly merged ops mid-round.
    let a_before = clone_log(&a.log);
    let b_before = clone_log(&b.log);
    let ca = pull(&mut a, &b_before, OrderKey::MIN, &reg);
    let cb = pull(&mut b, &a_before, OrderKey::MIN, &reg);

    assert_eq!(a.get("a"), Some(b"from-a".to_vec()));
    assert_eq!(a.get("b"), Some(b"from-b".to_vec()));
    assert_eq!(b.get("a"), Some(b"from-a".to_vec()));
    assert_eq!(b.get("b"), Some(b"from-b".to_vec()));
    assert_eq!(a.log.len(), 2);
    assert_eq!(b.log.len(), 2);

    // Idempotent replay from the resume cursors: nothing new, state unchanged.
    let a_now = clone_log(&a.log);
    let b_now = clone_log(&b.log);
    pull(&mut a, &b_now, ca, &reg);
    pull(&mut b, &a_now, cb, &reg);
    assert_eq!(a.log.len(), 2);
    assert_eq!(b.log.len(), 2);
}

#[test]
fn concurrent_writes_resolve_identically() {
    let mut a = Node::new();
    let mut b = Node::new();

    a.commit(&KvOp::Put {
        key: "x".into(),
        value: b"x-from-a".to_vec(),
    });
    b.commit(&KvOp::Put {
        key: "x".into(),
        value: b"x-from-b".to_vec(),
    });

    let reg = registry_of(&[&a, &b]);
    let a_before = clone_log(&a.log);
    let b_before = clone_log(&b.log);
    pull(&mut a, &b_before, OrderKey::MIN, &reg);
    pull(&mut b, &a_before, OrderKey::MIN, &reg);

    // Both replicas pick the same winner from the total order.
    assert_eq!(a.get("x"), b.get("x"));
}

/// Copy a log's ops into a fresh log (test-only snapshot helper).
fn clone_log(log: &OpLog) -> OpLog {
    let mut out = OpLog::new();
    for op in log.iter() {
        out.append(op.clone());
    }
    out
}
