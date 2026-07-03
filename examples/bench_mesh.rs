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
//!
//! `--mode trickle` is the "Clash of Clans live sync" profile: instead of one
//! bulk burst, each node commits one `KvOp::Put` every `--trickle-ms` for
//! `--duration-secs`, and every op's value carries the commit wall-clock time
//! (UNIX nanoseconds, big-endian, in its leading bytes, then padded to
//! `--payload-bytes` to approximate a chat message). Any receiver computes the
//! one-way propagation delay of an op as `arrival_wall - embedded_commit_wall`,
//! needing no clock exchange beyond what the machines already run: tailnet Macs
//! keep NTP, so ~ms skew is acceptable when the latencies themselves are in the
//! hundreds of ms. That honesty caveat is echoed in the output metadata. The
//! pull loop runs concurrently the whole time; its existing 150ms cadence is the
//! effective client-side pull interval and is reported as such.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use proxy_node_server::harness::{MeshNode, rss_kib};
use proxy_node_server::{
    DeviceId, HttpPullSource, KvOp, KvStore, OpId, OrderKey, Store, learn_devices, register_peer,
    sync_once,
};

/// Leading bytes of every trickle op's value: the commit wall-clock time as
/// UNIX nanoseconds, big-endian (`u128`). Everything after is zero padding up to
/// `--payload-bytes`.
const TS_BYTES: usize = 16;

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
    /// Seconds to keep serving after convergence, so slower peers can finish
    /// pulling from this node before it disappears.
    #[arg(long, default_value_t = 30)]
    linger_secs: u64,
    /// `bulk` (one burst, then converge) or `trickle` (live per-op sync).
    #[arg(long, value_enum, default_value = "bulk")]
    mode: Mode,
    /// Trickle mode: milliseconds between this node's commits.
    #[arg(long, default_value_t = 500)]
    trickle_ms: u64,
    /// Trickle mode: how long this node keeps committing, in seconds.
    #[arg(long, default_value_t = 60)]
    duration_secs: u64,
    /// Trickle mode: bytes per op value (>= 16; leading 16 hold the timestamp),
    /// approximating a chat message rather than the 8-byte bulk counters.
    #[arg(long, default_value_t = 512)]
    payload_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    Bulk,
    Trickle,
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
    let node = Arc::new(MeshNode::spawn_on(args.listen).await);
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

    // Trickle mode owns its own commit/pull/summary flow; hand it the shared
    // context and return before the bulk path below (left byte-for-byte intact).
    if args.mode == Mode::Trickle {
        run_trickle(
            &node,
            &mut peers,
            &args,
            settle,
            &self_hex,
            startup_ms,
            peers_ready_ms,
            &samples,
            &stop,
            sampler,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(args.linger_secs)).await;
        return;
    }

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

            // Track head stability for the settle rule. A fetch failure does
            // NOT block settling: a peer that converged first and exited (or
            // dropped off) after we drained it still counts once its last
            // observed head has been stable for the window — otherwise the
            // fastest node's exit strands everyone still watching it.
            if let Ok(head) = peer.source.fetch_head().await {
                if head != peer.last_head {
                    peer.last_head = head;
                    peer.head_changed_at = Instant::now();
                }
            }
            let stable = peer.head_changed_at.elapsed() >= settle;
            let nonempty = peer.last_head != OrderKey::MIN;
            let drained = peer.cursor >= peer.last_head;
            if stable && nonempty && drained && !peer.settled {
                peer.settled = true;
                peer.settled_ms = Some(start.elapsed().as_secs_f64() * 1e3);
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
    // Keep serving so slower peers can drain this node before it disappears.
    tokio::time::sleep(Duration::from_secs(args.linger_secs)).await;
}

/// UNIX wall-clock time in nanoseconds — the reference both the committer (embed)
/// and the receiver (arrival) read, so one-way delay needs no clock handshake.
fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}

/// Nearest-rank percentile over an already-sorted ascending slice. Empty → 0.
fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (((sorted.len() - 1) as f64) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Trickle mode: commit a timestamped op every `--trickle-ms` for
/// `--duration-secs` while the pull loop runs concurrently, timing each remote
/// op's propagation delay from its embedded commit time to local arrival.
#[allow(clippy::too_many_arguments)]
async fn run_trickle(
    node: &Arc<MeshNode>,
    peers: &mut [Peer],
    args: &Args,
    settle: Duration,
    self_hex: &str,
    startup_ms: f64,
    peers_ready_ms: f64,
    samples: &Arc<Mutex<Vec<(f64, f64)>>>,
    stop: &Arc<AtomicBool>,
    sampler: tokio::task::JoinHandle<()>,
) {
    let self_device: DeviceId = node.identity.device_id();
    let trickle = Duration::from_millis(args.trickle_ms.max(1));
    let payload_bytes = args.payload_bytes.max(TS_BYTES);
    // Commit count is fixed from duration/interval, so every node running the
    // same params sends the same number — the symmetric expectation "never
    // received" is measured against.
    let n_commits = ((args.duration_secs * 1000) / args.trickle_ms.max(1)).max(1) as usize;

    // Committer task: one Put every `trickle`, value = commit wall time (UNIX
    // nanos, big-endian) in the leading TS_BYTES, then zero padding.
    let sent = Arc::new(AtomicUsize::new(0));
    let commits_done = Arc::new(AtomicBool::new(false));
    let committer = {
        let node = node.clone();
        let sent = sent.clone();
        let commits_done = commits_done.clone();
        let label = args.label.clone();
        tokio::spawn(async move {
            for i in 0..n_commits {
                let mut value = vec![0u8; payload_bytes];
                value[..TS_BYTES].copy_from_slice(&unix_nanos().to_be_bytes());
                node.commit(&KvOp::Put {
                    key: format!("{label}/t{i}"),
                    value,
                });
                sent.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(trickle).await;
            }
            commits_done.store(true, Ordering::Relaxed);
        })
    };

    println!(
        "{{\"event\":\"trickle_start\",\"label\":\"{}\",\"n_commits\":{n_commits},\
\"trickle_ms\":{},\"duration_secs\":{},\"payload_bytes\":{payload_bytes},\"pull_loop_ms\":150}}",
        args.label, args.trickle_ms, args.duration_secs
    );

    let template = KvStore::new();
    let mut seen: HashSet<OpId> = HashSet::new();
    let mut last_len = 0usize;
    let mut latencies: Vec<f64> = Vec::new();
    let mut received: HashMap<String, usize> = HashMap::new();
    let mut last_progress = Instant::now();
    let mut drain_deadline: Option<Instant> = None;

    loop {
        for peer in peers.iter_mut() {
            if let Err(e) = sync_once(
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
                eprintln!("pull {}: {e}", peer.base);
                let _ = learn_devices(&peer.source, &node.registry).await;
            }
            if let Ok(head) = peer.source.fetch_head().await {
                peer.last_head = head;
            }
        }

        // Pick up ops applied since the last pass. The log is append-only, so a
        // length change is the cheap gate; on a change we diff against `seen`
        // rather than `since(cursor)` because concurrent peers interleave by HLC
        // and a remote op can land below the current head. `arrival_ns` is read
        // once, right after the pull round, as the ops' local arrival time.
        let arrival_ns = unix_nanos();
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut authors: Vec<String> = Vec::new();
        {
            let log = node.log.lock().unwrap();
            let len = log.len();
            if len != last_len {
                for op in log.iter() {
                    if seen.insert(op.id) && op.body.device != self_device {
                        authors.push(op.body.device.to_hex());
                        batch.push(op.body.payload.clone());
                    }
                }
                last_len = len;
            }
        }
        for (payload, author) in batch.into_iter().zip(authors) {
            if let Ok(KvOp::Put { value, .. }) = template.decode(&payload) {
                if value.len() >= TS_BYTES {
                    let mut ts = [0u8; TS_BYTES];
                    ts.copy_from_slice(&value[..TS_BYTES]);
                    let commit_ns = u128::from_be_bytes(ts);
                    latencies.push(arrival_ns.saturating_sub(commit_ns) as f64 / 1e6);
                }
            }
            *received.entry(author).or_default() += 1;
        }

        if last_progress.elapsed() >= Duration::from_secs(5) {
            let mut sorted = latencies.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let recv_total: usize = received.values().sum();
            println!(
                "{{\"event\":\"progress\",\"label\":\"{}\",\"sent\":{},\"received\":{recv_total},\
\"p50_ms\":{:.3},\"p95_ms\":{:.3}}}",
                args.label,
                sent.load(Ordering::Relaxed),
                percentile(&sorted, 0.50),
                percentile(&sorted, 0.95),
            );
            last_progress = Instant::now();
        }

        // After the last commit, drain the tail for 2*settle before summarizing.
        if commits_done.load(Ordering::Relaxed) {
            let deadline = *drain_deadline.get_or_insert_with(|| Instant::now() + 2 * settle);
            if Instant::now() >= deadline {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let _ = committer.await;
    let sent_total = sent.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = sampler.await;

    let mut sorted = latencies.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&sorted, 0.50);
    let p95 = percentile(&sorted, 0.95);
    let p99 = percentile(&sorted, 0.99);
    let max = sorted.last().copied().unwrap_or(0.0);

    let received_total: usize = received.values().sum();
    let never_total: usize = peers
        .iter()
        .map(|p| sent_total.saturating_sub(received.get(&p.device_hex).copied().unwrap_or(0)))
        .sum();

    let peers_json = peers
        .iter()
        .map(|p| {
            let recv = received.get(&p.device_hex).copied().unwrap_or(0);
            let never = sent_total.saturating_sub(recv);
            let drained = p.cursor >= p.last_head;
            format!(
                "{{\"base\":\"{}\",\"device\":\"{}\",\"received\":{recv},\
\"never_received\":{never},\"drained\":{drained}}}",
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
        "{{\"event\":\"summary\",\"mode\":\"trickle\",\"label\":\"{}\",\"device\":\"{}\",\
\"startup_ms\":{startup_ms:.3},\"peers_ready_ms\":{peers_ready_ms:.3},\
\"trickle_ms\":{},\"duration_secs\":{},\"payload_bytes\":{payload_bytes},\"pull_loop_ms\":150,\
\"sent\":{sent_total},\"received\":{received_total},\"never_received\":{never_total},\
\"latency_p50_ms\":{p50:.3},\"latency_p95_ms\":{p95:.3},\"latency_p99_ms\":{p99:.3},\
\"latency_max_ms\":{max:.3},\
\"clock_note\":\"latency = arrival_wall - embedded_commit_wall (UNIX nanos); tailnet Macs run NTP, so ~ms skew is acceptable at ~hundreds-of-ms latencies\",\
\"peers\":[{peers_json}],\"rss_mb\":[{rss_json}]}}",
        args.label, self_hex, args.trickle_ms, args.duration_secs
    );
}
