//! N-daemon end-to-end convergence over the HTTP pull transport, using the
//! in-process [`harness`](proxy_node_server::harness). Generalizes
//! `two_node_sync` to N nodes and adds the transitive device-key propagation
//! case (D11): a node must be able to verify ops relayed from a device it never
//! contacted, once a peer gossips that device's key over `/devices`.
#![cfg(feature = "harness")]

use proxy_node_server::KvOp;
use proxy_node_server::harness::{MeshNode, converge, heads_equal, spawn_mesh};

#[tokio::test]
async fn n_nodes_converge_on_distinct_writes() {
    let nodes = spawn_mesh(4).await;
    for (i, node) in nodes.iter().enumerate() {
        node.commit(&KvOp::Put {
            key: format!("k{i}"),
            value: format!("from-{i}").into_bytes(),
        });
    }

    let rounds = converge(&nodes, 6).await;
    assert!(
        heads_equal(&nodes),
        "mesh did not converge in {rounds} rounds"
    );

    // Every node holds all four ops and agrees on every key.
    for node in &nodes {
        assert_eq!(node.log_len(), 4);
        for i in 0..4 {
            assert_eq!(
                node.get(&format!("k{i}")),
                Some(format!("from-{i}").into_bytes())
            );
        }
    }

    // Idempotent: another full round changes nothing.
    converge(&nodes, 1).await;
    for node in &nodes {
        assert_eq!(node.log_len(), 4);
    }
}

#[tokio::test]
async fn n_nodes_resolve_one_key_identically() {
    let nodes = spawn_mesh(3).await;
    for (i, node) in nodes.iter().enumerate() {
        node.commit(&KvOp::Put {
            key: "x".into(),
            value: format!("x-from-{i}").into_bytes(),
        });
    }

    converge(&nodes, 6).await;

    // LWW by the (hlc, device, op_id) total order picks one winner everywhere.
    let winner = nodes[0].get("x");
    assert!(winner.is_some());
    for node in &nodes {
        assert_eq!(node.get("x"), winner);
        assert_eq!(node.log_len(), 3);
    }
}

// D11: A only ever pulls B; C's op reaches A because B relays the op and gossips
// C's key over /devices. Without transitive key propagation, A would abort on
// C's op as an unknown device.
#[tokio::test]
async fn key_and_ops_propagate_transitively() {
    let a = MeshNode::spawn().await;
    let b = MeshNode::spawn().await;
    let c = MeshNode::spawn().await;

    c.commit(&KvOp::Put {
        key: "kc".into(),
        value: b"from-c".to_vec(),
    });

    // B learns C's key + op directly.
    b.sync_from(&c).await;
    assert_eq!(b.get("kc"), Some(b"from-c".to_vec()));

    // A only contacts B. It must learn C's key from B's /devices gossip and then
    // verify C's op that B relays — never having contacted C.
    a.sync_from(&b).await;
    assert_eq!(
        a.get("kc"),
        Some(b"from-c".to_vec()),
        "C's op did not propagate transitively through B"
    );
    assert!(
        a.registry.lock().unwrap().contains(&c.identity.device_id()),
        "A did not learn C's key via /devices gossip"
    );
}
