//! Real multi-machine mesh benchmark node (feature `harness`). Unlike the
//! in-process examples, this is a single self-contained node meant to run on N
//! machines at once: each instance serves its own op-log on a real address and
//! pulls from the peers it is told about. Point three instances at each other
//! and watch a fresh op cross the whole mesh.
//!
//! Run one instance per machine, each listing the others as peers, e.g.:
//!
//! ```text
//! # machine A
//! cargo run --release --features harness --example bench_mesh -- \
//!     --listen 0.0.0.0:51713 --label a --commit 100 \
//!     --peer http://B:51713 --peer http://C:51713
//! ```
//!
//! Each node generates a throwaway identity (nothing is persisted — the whole
//! run is disposable), waits for every peer to answer `/identity` (peers may
//! start seconds apart), commits `--commit` ops under a key namespace derived
//! from `--label` so ops from different nodes never collide, then pulls from
//! every peer until it has converged.
//!
//! Convergence rule (the simplest robust one that needs no out-of-band
//! coordination): a peer is *settled* once the `OrderKey` it serves at `/head`
//! has been unchanged for `--settle-secs` — that is how long it must be quiet
//! before we trust it has stopped committing. Once every peer is settled and
//! this node's pull cursor has reached each peer's head (it has pulled each peer
//! to exhaustion), the mesh has converged: the local log then holds this node's
//! own N ops plus, for each peer, exactly the ops that peer authored. This
//! assumes every node commits at least one op (a node that commits nothing keeps
//! an empty log and never leaves the `MIN` head, so it is never declared
//! settled). No assertions — the functional tests own pass/fail; this only
//! records numbers, one JSON object per line, and exits 0.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use proxy_node_server::harness::{MeshNode, rss_kib};
use proxy_node_server::{HttpPullSource, KvOp, OrderKey, learn_devices, register_peer, sync_once};

#[derive(Parser)]
#[command(about = "One mesh-benchmark node: serve, peer, commit, converge.")]
struct Args {
    /// Address to bind this node's pull server on, e.g. 0.0.0.0:51713.
    #[arg(long)]
    listen: SocketAddr,
    /// Peer base URL to pull from (repeatable), e.g. http://10.0.0.5:51713.
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Number of `KvOp::Put` ops this node commits locally.
    #[arg(long, default_value_t = 100)]
    commit: usize,
    /// Label for this node; namespaces its keys and tags output.
    #[arg(long, default_value = "node")]
    label: String,
    /// Seconds a peer's `/head` must be unchanged before it is declared settled.
    #[arg(long, default_value_t = 5)]
    settle_secs: u64,
    /// RSS sample period in milliseconds.
    #[arg(long, default_value_t = 1000)]
    sample_ms: u64,
}

/// One peer this node pulls from, plus the state needed to detect it settling.
struct Peer {
    base: String,
    source: HttpPullSource,
    /// The peer's own device id, hex — used to count the ops it authored.
    device_hex: String,
    /// Resume cursor for pulling this peer.
    cursor: OrderKey,
    /// Last `/head` we observed and when it last changed, for settle detection.
    last_head: OrderKey,
    head_changed_at: Instant,
    settled: bool,
    /// Wall time from run start to when this peer first settled, in ms.
    settled_ms: Option<f64>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let settle = Duration::from_secs(args.settle_secs);
    let start = Instant::now();
    let pid = std::process::id();

    println!(
        "{{\"bench\":\"mesh\",\"label\":\"{}\",\"listen\":\"{}\",\"peer_count\":{},\"commit\":{}}}",
        args.label,
        args.listen,
        args.peers.len(),
        args.commit
    );

    // Background RSS sampler: runs for the whole session, one reading every
    // `--sample-ms`, so the series spans startup, peer wait, commit, and pull.
    let samples: Arc<Mutex<Vec<(f64, f64)>>> = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let samples = samples.clone();
        let stop = stop.clone();
        let period = Duration::from_millis(args.sample_ms);
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let mb = rss_kib(pid).unwrap_or(0) as f64 / 1024.0;
                let t_ms = start.elapsed().as_secs_f64() * 1e3;
                samples.lock().unwrap().push((t_ms, mb));
                tokio::time::sleep(period).await;
            }
        })
    };

    // Startup: bind the server and start serving. Once `spawn_on` returns, the
    // identity exists and `/identity`, `/head`, `/ops`, `/devices` are live.
    let node = MeshNode::spawn_on(args.listen).await;
    let self_hex = node.identity.device_id().to_hex();
    let startup_ms = start.elapsed().as_secs_f64() * 1e3;
    println!(
        "{{\"event\":\"startup\",\"label\":\"{}\",\"device\":\"{}\",\"startup_ms\":{startup_ms:.3}}}",
        args.label, self_hex
    );

    // Wait-retry until every peer answers `/identity`, then register + learn its
    // keys. Peers may boot seconds apart, so a failed probe is expected, not
    // fatal: retry on the client's 3s per-request timeout.
    let mut peers: Vec<Peer> = Vec::with_capacity(args.peers.len());
    for base in &args.peers {
        let source = HttpPullSource::new(base);
        let device = loop {
            match register_peer(&source, &node.registry).await {
                Ok((device, _)) => break device,
                Err(e) => {
                    eprintln!("waiting for peer {base}: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        };
        // Adopt the devices this peer vouches for, so ops it relays from third
        // parties verify. Best-effort; a flaky /devices is retried on pull error.
        let _ = learn_devices(&source, &node.registry).await;
        peers.push(Peer {
            base: base.clone(),
            source,
            device_hex: device.to_hex(),
            cursor: OrderKey::MIN,
            last_head: OrderKey::MIN,
            head_changed_at: Instant::now(),
            settled: false,
            settled_ms: None,
        });
    }
    let peers_ready_ms = start.elapsed().as_secs_f64() * 1e3;
    println!(
        "{{\"event\":\"peers_ready\",\"label\":\"{}\",\"peers_ready_ms\":{peers_ready_ms:.3}}}",
        args.label
    );

    // Commit this node's ops. Keys are namespaced by label so two nodes writing
    // "the same" index never collide in the shared store.
    for i in 0..args.commit {
        node.commit(&KvOp::Put {
            key: format!("{}/k{i}", args.label),
            value: (i as u64).to_le_bytes().to_vec(),
        });
    }
    println!(
        "{{\"event\":\"committed\",\"label\":\"{}\",\"n\":{}}}",
        args.label, args.commit
    );

    // Pull loop until convergence. `first_pull_at` anchors converged_ms; it stays
    // None when there are no peers, so a lone node converges instantly.
    let mut first_pull_at: Option<Instant> = None;
    loop {
        for peer in &mut peers {
            first_pull_at.get_or_insert_with(Instant::now);
            match sync_once(
                &peer.source,
                &node.registry,
                &node.clock,
                &node.log,
                &node.store,
                &mut peer.cursor,
                None,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    // Peer flakiness or a relayed op from a not-yet-known device:
                    // never fatal. Re-learn the peer's device set and retry next
                    // round. The cursor only advanced over verified ops, so no
                    // progress is lost.
                    eprintln!("pull {}: {e}", peer.base);
                    let _ = learn_devices(&peer.source, &node.registry).await;
                }
            }

            // Track head stability for the settle rule.
            if let Ok(head) = peer.source.fetch_head().await {
                if head != peer.last_head {
                    peer.last_head = head;
                    peer.head_changed_at = Instant::now();
                }
                let stable = peer.head_changed_at.elapsed() >= settle;
                let nonempty = head != OrderKey::MIN;
                if stable && nonempty && !peer.settled {
                    peer.settled = true;
                    peer.settled_ms = Some(start.elapsed().as_secs_f64() * 1e3);
                }
            }
        }

        // Converged when every peer is settled and this node has pulled each peer
        // to its head (cursor reached the peer's stable head).
        let converged = peers.iter().all(|p| p.settled && p.cursor >= p.last_head);
        if converged {
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let converged_ms = first_pull_at
        .map(|t| t.elapsed().as_secs_f64() * 1e3)
        .unwrap_or(0.0);

    // Per-device op counts in the final log: this node's own (should equal N)
    // plus each peer's authored ops — the "expected count" the convergence rule
    // is built on.
    let (log_len, counts) = {
        let log = node.log.lock().unwrap();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for op in log.iter() {
            *counts.entry(op.body.device.to_hex()).or_default() += 1;
        }
        (log.len(), counts)
    };
    let self_ops = counts.get(&self_hex).copied().unwrap_or(0);

    // Pull throughput: remote ops materialized locally per second of the
    // convergence window (this node's own N were committed before it began).
    let pulled = log_len.saturating_sub(self_ops);
    let converged_secs = converged_ms / 1e3;
    let ops_per_s = if converged_secs > 0.0 {
        pulled as f64 / converged_secs
    } else {
        0.0
    };

    stop.store(true, Ordering::Relaxed);
    let _ = sampler.await;

    let peers_json = peers
        .iter()
        .map(|p| {
            let ops = counts.get(&p.device_hex).copied().unwrap_or(0);
            let settled = p.settled_ms.unwrap_or(0.0);
            format!(
                "{{\"base\":\"{}\",\"device\":\"{}\",\"ops\":{ops},\"settled_ms\":{settled:.3}}}",
                p.base, p.device_hex
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let rss_json = samples
        .lock()
        .unwrap()
        .iter()
        .map(|(t, mb)| format!("{{\"t_ms\":{t:.1},\"mb\":{mb:.2}}}"))
        .collect::<Vec<_>>()
        .join(",");

    println!(
        "{{\"event\":\"summary\",\"label\":\"{}\",\"device\":\"{}\",\
\"startup_ms\":{startup_ms:.3},\"peers_ready_ms\":{peers_ready_ms:.3},\
\"committed\":{},\"self_ops\":{self_ops},\"converged_ms\":{converged_ms:.3},\
\"log_len\":{log_len},\"ops_per_s\":{ops_per_s:.1},\
\"peers\":[{peers_json}],\"rss_mb\":[{rss_json}]}}",
        args.label, self_hex, args.commit
    );
}
