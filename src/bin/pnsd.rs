//! `pnsd` — the reference daemon. It proves device-key generation, key-import
//! parity with the Swift app, and the derived device id. Under the `pull-http`
//! feature it also serves its op-log and pulls from configured peers.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use proxy_node_server::{DeviceIdentity, ENVELOPE_VERSION};

const KEY_FILE: &str = "device.key";
#[cfg(feature = "pull-http")]
const OPLOG_FILE: &str = "oplog.bin";
const DEFAULT_DATA_DIR: &str = "./pns-data";

#[derive(Parser)]
#[command(
    name = "pnsd",
    about = "Proxy node server reference daemon",
    disable_version_flag = true
)]
struct Cli {
    /// Print crate version and envelope version.
    #[arg(long)]
    version: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Device identity management.
    Identity {
        #[command(subcommand)]
        action: IdentityCmd,
    },
    /// Serve this node's op-log and pull from configured peers.
    #[cfg(feature = "pull-http")]
    Serve {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Address to bind the pull server on.
        #[arg(long, default_value = "127.0.0.1:51713")]
        listen: std::net::SocketAddr,
        /// Peer base URL to pull from (repeatable), e.g. http://127.0.0.1:51713.
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Use the legacy semantic-order v1 pull/watch protocol. This is never
        /// selected automatically when relay v2 is unavailable.
        #[arg(long)]
        legacy_v1: bool,
        /// Fallback poll interval, in seconds, used when a watch errors.
        #[arg(long, default_value_t = 2)]
        pull_interval: u64,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Create the device identity. Fails if one already exists.
    Init {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Load a raw 32-byte P-256 scalar from this file instead of generating.
        #[arg(long)]
        import_raw: Option<PathBuf>,
    },
    /// Print the persisted DeviceId and compressed SEC1 public key.
    Show {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.version {
        println!(
            "pnsd {} (envelope v{})",
            env!("CARGO_PKG_VERSION"),
            ENVELOPE_VERSION
        );
        return ExitCode::SUCCESS;
    }

    let result = match cli.command {
        Some(Command::Identity { action }) => run_identity(action),
        #[cfg(feature = "pull-http")]
        Some(Command::Serve {
            data_dir,
            listen,
            peers,
            legacy_v1,
            pull_interval,
        }) => serve::run(
            resolve_data_dir(data_dir),
            listen,
            peers,
            legacy_v1,
            pull_interval,
        ),
        None => {
            eprintln!("no command given; try `pnsd --help`");
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_identity(action: IdentityCmd) -> Result<(), String> {
    match action {
        IdentityCmd::Init {
            data_dir,
            import_raw,
        } => identity_init(resolve_data_dir(data_dir), import_raw),
        IdentityCmd::Show { data_dir, json } => identity_show(resolve_data_dir(data_dir), json),
    }
}

fn identity_init(data_dir: PathBuf, import_raw: Option<PathBuf>) -> Result<(), String> {
    let key_path = data_dir.join(KEY_FILE);
    if key_path.exists() {
        return Err(format!("{} already exists", key_path.display()));
    }
    fs::create_dir_all(&data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;

    let identity = match import_raw {
        Some(path) => {
            let scalar = read_scalar(&path)?;
            DeviceIdentity::import_raw(&scalar).map_err(|e| format!("import key: {e}"))?
        }
        None => DeviceIdentity::generate(),
    };

    write_key(&key_path, &identity)?;
    println!("{}", identity.device_id());
    Ok(())
}

fn identity_show(data_dir: PathBuf, json: bool) -> Result<(), String> {
    let key_path = data_dir.join(KEY_FILE);
    let scalar = read_scalar(&key_path)?;
    let identity = DeviceIdentity::import_raw(&scalar).map_err(|e| format!("load key: {e}"))?;

    let device_id = identity.device_id().to_hex();
    let sec1 = hex(&identity.public_key_sec1());

    if json {
        let value = serde_json::json!({
            "device_id": device_id,
            "public_key_sec1": sec1,
        });
        println!("{value}");
    } else {
        println!("device_id:       {device_id}");
        println!("public_key_sec1: {sec1}");
    }
    Ok(())
}

fn resolve_data_dir(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| std::env::var_os("PNS_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

fn read_scalar(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{}: expected 32 raw scalar bytes, got {}",
            path.display(),
            bytes.len()
        ));
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&bytes);
    Ok(scalar)
}

fn write_key(path: &Path, identity: &DeviceIdentity) -> Result<(), String> {
    use std::io::Write;
    let scalar = identity.export_raw();
    let mut file = create_key_file(path)?;
    file.write_all(scalar.as_ref())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

/// Create the key file with owner-only permissions at creation time. `create_new`
/// fails if the path already exists, so the private key is never written through
/// a pre-existing, possibly world-readable, file.
#[cfg(unix)]
fn create_key_file(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn create_key_file(path: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(feature = "pull-http")]
mod serve {
    use std::future::Future;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use proxy_node_server::{
        DeviceId, DeviceIdentity, DeviceRegistry, HeadPublisher, HttpPullSource, KvStore,
        NodeClock, OpLog, OplogWriter, OrderKey, RelayCursorV2, RelayPageV2, ServeState,
        TransportError, WATCH_DEFAULT_WAIT, WATCH_EMPTY_BACKOFF, learn_attested_devices,
        learn_devices, load_cursor, load_peer_keys, load_relay_caller_keys, load_relay_cursor,
        register_peer_with_key, relay_router, replay, replay_oplog_file, router, save_cursor,
        save_peer_keys, save_relay_caller_keys, save_relay_cursor, sync_once, sync_relay_once_v2,
    };

    use super::{KEY_FILE, OPLOG_FILE, read_scalar};

    /// How long a peer stays poll-only after its selected protocol's `/watch`
    /// errors before the loop re-probes it. Relay-v2 errors never select v1.
    const WATCH_REPROBE_INTERVAL: Duration = Duration::from_secs(300);

    /// One resolved peer to pull from: its client, device id, resume cursor, and
    /// per-link watch capability. `poll_only_until` is `None` while the peer is
    /// treated as push-capable (included in the `/watch` race); `Some(deadline)`
    /// after its selected `/watch` errored, so it is pulled with the same protocol
    /// on the fallback interval until `deadline`, when its watch is re-probed.
    struct Link {
        source: HttpPullSource,
        peer_id: DeviceId,
        peer_key: [u8; 33],
        relay_cursor: RelayCursorV2,
        legacy_cursor: OrderKey,
        poll_only_until: Option<Instant>,
    }

    /// Race the `/watch` of the currently push-capable links (indices into
    /// `links`), resolving as soon as the first responds — a head change (new ops
    /// to pull), a clean hold-window close, or an error (e.g. 404 on a pre-push
    /// peer). Returns `(link index, result)` so the caller can mark exactly the
    /// peer that answered. `capable` must be non-empty; each `watch_head` future
    /// carries its own bounded timeout, so one always resolves. Dependency-free
    /// `select_all`.
    async fn wait_for_any_legacy_watch(
        links: &[Link],
        capable: &[usize],
        wait: Duration,
    ) -> (usize, Result<OrderKey, TransportError>) {
        let mut futures: Vec<_> = capable
            .iter()
            .map(|&i| {
                (
                    i,
                    Box::pin(links[i].source.watch_head(links[i].legacy_cursor, wait)),
                )
            })
            .collect();
        std::future::poll_fn(|cx| {
            for (i, future) in futures.iter_mut() {
                if let Poll::Ready(result) = future.as_mut().poll(cx) {
                    return Poll::Ready((*i, result));
                }
            }
            Poll::Pending
        })
        .await
    }

    async fn wait_for_any_relay_watch(
        identity: &DeviceIdentity,
        links: &[Link],
        capable: &[usize],
        wait: Duration,
    ) -> (usize, Result<RelayPageV2, TransportError>) {
        let mut futures: Vec<_> = capable
            .iter()
            .map(|&i| {
                (
                    i,
                    Box::pin(links[i].source.watch_relay_head_v2(
                        identity,
                        links[i].peer_id,
                        &links[i].peer_key,
                        links[i].relay_cursor,
                        wait,
                    )),
                )
            })
            .collect();
        std::future::poll_fn(|cx| {
            for (i, future) in futures.iter_mut() {
                if let Poll::Ready(result) = future.as_mut().poll(cx) {
                    return Poll::Ready((*i, result));
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Reconnect jitter in `0.5..1.5 × base`, so N daemons that all lost a
    /// restarting peer do not re-probe it in lockstep. Uses wall-clock nanos as
    /// cheap entropy — no rng dependency for a coarse spread.
    fn jitter(base: Duration) -> Duration {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        base.mul_f64(0.5 + f64::from(nanos) / f64::from(u32::MAX))
    }

    pub fn run(
        data_dir: PathBuf,
        listen: SocketAddr,
        peers: Vec<String>,
        legacy_v1: bool,
        pull_interval: u64,
    ) -> Result<(), String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
        rt.block_on(serve(data_dir, listen, peers, legacy_v1, pull_interval))
    }

    async fn serve(
        data_dir: PathBuf,
        listen: SocketAddr,
        peers: Vec<String>,
        legacy_v1: bool,
        pull_interval: u64,
    ) -> Result<(), String> {
        let scalar = read_scalar(&data_dir.join(KEY_FILE))?;
        let identity =
            Arc::new(DeviceIdentity::import_raw(&scalar).map_err(|e| format!("load key: {e}"))?);
        let clock = NodeClock::new(&identity.device_id());

        let mut registry = DeviceRegistry::new();
        registry.insert_key(*identity.verifying_key());
        // Peer keys must be in the registry BEFORE the replay below, or ops
        // previously pulled (and fsynced) from peers read as unknown-device
        // frames and vanish from memory while the cursors still say they were
        // pulled.
        let known = load_peer_keys(&data_dir, &mut registry);
        if known > 0 {
            println!("loaded {known} known peer key(s)");
        }
        // Shared so the /devices route gossips these keys while the pull loop
        // both learns new ones and verifies pulled ops against them.
        let registry = Arc::new(Mutex::new(registry));

        let mut relay_callers = DeviceRegistry::new();
        relay_callers.insert_key(*identity.verifying_key());
        let known_relay_callers = load_relay_caller_keys(&data_dir, &mut relay_callers);
        if known_relay_callers > 0 {
            println!("loaded {known_relay_callers} direct relay caller key(s)");
        }
        let relay_callers = Arc::new(Mutex::new(relay_callers));

        let oplog_path = data_dir.join(OPLOG_FILE);
        let log = Arc::new(Mutex::new(OpLog::new()));
        let store = Mutex::new(KvStore::new());
        {
            let mut log = log.lock().expect("oplog mutex poisoned");
            replay_oplog_file(
                &oplog_path,
                &registry.lock().expect("registry mutex poisoned"),
                &mut log,
            )
            .map_err(|e| format!("replay oplog: {e}"))?;
            let mut store = store.lock().expect("store mutex poisoned");
            replay(&log, &mut *store).map_err(|e| format!("replay store: {e}"))?;
        }
        let writer =
            Mutex::new(OplogWriter::open(&oplog_path).map_err(|e| format!("open oplog: {e}"))?);

        // Push publisher for this node's own `/watch`: peers watching us are woken
        // the instant we append (relay) an op, instead of polling. Seeded with the
        // post-replay head; correctness always reads the authoritative log head.
        let head_pub = HeadPublisher::new(
            log.lock()
                .expect("oplog mutex poisoned")
                .head()
                .unwrap_or(OrderKey::MIN),
        );

        let state = ServeState::new(identity.clone(), log.clone(), registry.clone())
            .with_relay_callers(relay_callers.clone())
            .with_watch(head_pub.watch());
        let app = if legacy_v1 {
            router(state)
        } else {
            relay_router(state)
        };
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        println!("pnsd serving {} on {listen}", identity.device_id());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("server exited: {e}");
            }
        });

        let mut links: Vec<Link> = Vec::new();
        let mut learned_keys = false;
        for base in peers {
            let source = HttpPullSource::new(&base);
            match register_peer_with_key(&source, &registry).await {
                Ok((peer_id, peer_key, newly_added)) => {
                    // A NEWLY learned key that fails to persist must not
                    // verify ops at all — not for this peer's target, and not
                    // transitively via other peers' logs — or a cursor could
                    // advance past ops the next startup replay skips as
                    // unknown-device. Evict exactly what this registration
                    // introduced and skip the peer. A key that was already
                    // durable (peers.bin, or the local identity) stays: the
                    // failed save is atomic and left the old file intact, so
                    // pulling with it is safe.
                    if newly_added {
                        if let Err(e) =
                            save_peer_keys(&data_dir, &registry.lock().expect("registry poisoned"))
                        {
                            registry.lock().expect("registry poisoned").remove(&peer_id);
                            eprintln!("persist peer keys: {e}; skipping peer {base} this run");
                            continue;
                        }
                        learned_keys = true;
                    }
                    let newly_added_relay_caller = {
                        let mut callers = relay_callers.lock().expect("relay callers poisoned");
                        let newly_added = !callers.contains(&peer_id);
                        callers
                            .insert_sec1(&peer_key)
                            .map_err(|e| format!("register relay caller {peer_id}: {e}"))?;
                        newly_added
                    };
                    if newly_added_relay_caller {
                        if let Err(e) = save_relay_caller_keys(
                            &data_dir,
                            &relay_callers.lock().expect("relay callers poisoned"),
                        ) {
                            relay_callers
                                .lock()
                                .expect("relay callers poisoned")
                                .remove(&peer_id);
                            eprintln!(
                                "persist direct relay caller: {e}; skipping peer {base} this run"
                            );
                            continue;
                        }
                    }
                    // Gossip: adopt every device this peer vouches for so ops it
                    // relays from third parties verify. Same durability rule —
                    // persist before pulling, roll back exactly what we added on
                    // a failed save so no un-persisted key ever verifies an op.
                    let learned = if legacy_v1 {
                        learn_devices(&source, &registry).await
                    } else {
                        learn_attested_devices(&source, peer_id, &peer_key, &registry).await
                    };
                    match learned {
                        Ok(added) if !added.is_empty() => {
                            if let Err(e) = save_peer_keys(
                                &data_dir,
                                &registry.lock().expect("registry poisoned"),
                            ) {
                                let mut reg = registry.lock().expect("registry poisoned");
                                for id in &added {
                                    reg.remove(id);
                                }
                                eprintln!("persist gossiped keys from {base}: {e}");
                            } else {
                                learned_keys = true;
                                println!("learned {} device key(s) via {peer_id}", added.len());
                            }
                        }
                        Ok(_) => {}
                        Err(e) => eprintln!("learn devices {base}: {e}"),
                    }
                    let relay_cursor = load_relay_cursor(&data_dir, &peer_id);
                    let legacy_cursor = load_cursor(&data_dir, &peer_id);
                    let protocol = if legacy_v1 { "legacy v1" } else { "relay v2" };
                    println!("peer {peer_id} at {base} ({protocol})");
                    links.push(Link {
                        source,
                        peer_id,
                        peer_key,
                        relay_cursor,
                        legacy_cursor,
                        poll_only_until: None,
                    });
                }
                Err(e) => eprintln!("register peer {base}: {e}"),
            }
        }

        // The startup replay ran before these keys existed (first run, or a
        // lost/corrupt peers.bin): frames it skipped as unknown-device are
        // recoverable NOW that the registry is complete, not at next restart.
        // OpLog::append dedups, so re-replaying is idempotent.
        if learned_keys {
            let mut log = log.lock().expect("oplog mutex poisoned");
            let recovered = replay_oplog_file(
                &oplog_path,
                &registry.lock().expect("registry mutex poisoned"),
                &mut log,
            )
            .map_err(|e| format!("re-replay oplog: {e}"))?;
            if recovered > 0 {
                println!("recovered {recovered} op(s) for newly known peers");
                let mut store = store.lock().expect("store mutex poisoned");
                replay(&log, &mut *store).map_err(|e| format!("replay store: {e}"))?;
                if let Some(head) = log.head() {
                    head_pub.publish(head);
                }
            }
        }

        // `--pull-interval` is the per-link fallback/jitter cadence. A relay-v2
        // watch failure switches only that link to relay-v2 polling; it never
        // selects the legacy protocol.
        let interval = Duration::from_secs(pull_interval);
        loop {
            // 1. Drain every peer to exhaustion, so a short-limit page never waits
            //    on the watch/timer — pagination spins pages with no sleep. Both
            //    push-capable and poll-only peers are pulled here each round.
            for link in &mut links {
                loop {
                    if legacy_v1 {
                        let before = link.legacy_cursor;
                        let result = sync_once(
                            &link.source,
                            &registry,
                            &clock,
                            &log,
                            &store,
                            &mut link.legacy_cursor,
                            Some(&writer),
                        )
                        .await;
                        if link.legacy_cursor != before {
                            if let Err(e) =
                                save_cursor(&data_dir, &link.peer_id, link.legacy_cursor)
                            {
                                eprintln!("save cursor {}: {e}", link.peer_id);
                            }
                        }
                        let applied = match &result {
                            Ok(n) if *n > 0 => {
                                println!("pulled {n} op(s) from {}", link.peer_id);
                                if let Some(head) = log.lock().expect("oplog mutex poisoned").head()
                                {
                                    head_pub.publish(head);
                                }
                                *n
                            }
                            Ok(_) => 0,
                            Err(e) => {
                                eprintln!("pull {}: {e}", link.peer_id);
                                0
                            }
                        };
                        if applied == 0 || link.legacy_cursor == before {
                            break;
                        }
                    } else {
                        let before = link.relay_cursor;
                        let result = sync_relay_once_v2(
                            &link.source,
                            &identity,
                            link.peer_id,
                            &link.peer_key,
                            &registry,
                            &clock,
                            &log,
                            &store,
                            &mut link.relay_cursor,
                            Some(&writer),
                        )
                        .await;
                        if link.relay_cursor != before {
                            if let Err(e) =
                                save_relay_cursor(&data_dir, &link.peer_id, link.relay_cursor)
                            {
                                eprintln!("save relay cursor {}: {e}", link.peer_id);
                            }
                        }
                        let keep_draining = match &result {
                            Ok(outcome) => {
                                if outcome.received > 0 {
                                    println!(
                                        "pulled {} relay op(s) from {}",
                                        outcome.received, link.peer_id
                                    );
                                }
                                if outcome.appended > 0 {
                                    if let Some(head) =
                                        log.lock().expect("oplog mutex poisoned").head()
                                    {
                                        head_pub.publish(head);
                                    }
                                }
                                outcome.received > 0 || outcome.reset
                            }
                            Err(e) => {
                                eprintln!("relay pull {}: {e}", link.peer_id);
                                false
                            }
                        };
                        if !keep_draining || link.relay_cursor == before {
                            break;
                        }
                    }
                }
            }

            // 2. Re-probe: a poll-only peer whose backoff elapsed rejoins the
            //    watch race, so an upgraded/restarted peer regains push delivery.
            let now = Instant::now();
            for link in &mut links {
                if link.poll_only_until.is_some_and(|deadline| now >= deadline) {
                    link.poll_only_until = None;
                }
            }

            // 3. Wait for the next pull trigger, per-link:
            //    - push-capable peers: block on their `/watch` race;
            //    - poll-only peers: bounded by the jittered fallback interval so
            //      they are pulled on their own cadence, never gated on a capable
            //      peer's watch;
            //    - no capable peers (or no peers): pure interval poll.
            let capable: Vec<usize> = links
                .iter()
                .enumerate()
                .filter(|(_, link)| link.poll_only_until.is_none())
                .map(|(i, _)| i)
                .collect();
            let any_poll_only = links.iter().any(|link| link.poll_only_until.is_some());

            if capable.is_empty() {
                tokio::time::sleep(jitter(interval)).await;
                continue;
            }

            // A watch that errors marks *only that peer* poll-only (with a
            // re-probe deadline); it never sleeps the interval on behalf of the
            // capable peers, and never short-circuits their wait.
            if legacy_v1 {
                let outcome = if any_poll_only {
                    tokio::select! {
                        resolved = wait_for_any_legacy_watch(&links, &capable, WATCH_DEFAULT_WAIT) => Some(resolved),
                        _ = tokio::time::sleep(jitter(interval)) => None,
                    }
                } else {
                    Some(wait_for_any_legacy_watch(&links, &capable, WATCH_DEFAULT_WAIT).await)
                };
                match outcome {
                    Some((idx, Err(e))) => {
                        eprintln!(
                            "watch {}: {e}; polling this peer until re-probe",
                            links[idx].peer_id
                        );
                        links[idx].poll_only_until = Some(Instant::now() + WATCH_REPROBE_INTERVAL);
                    }
                    Some((idx, Ok(head))) if head <= links[idx].legacy_cursor => {
                        tokio::time::sleep(WATCH_EMPTY_BACKOFF).await;
                    }
                    _ => {}
                }
            } else {
                let outcome = if any_poll_only {
                    tokio::select! {
                        resolved = wait_for_any_relay_watch(&identity, &links, &capable, WATCH_DEFAULT_WAIT) => Some(resolved),
                        _ = tokio::time::sleep(jitter(interval)) => None,
                    }
                } else {
                    Some(
                        wait_for_any_relay_watch(&identity, &links, &capable, WATCH_DEFAULT_WAIT)
                            .await,
                    )
                };
                match outcome {
                    Some((idx, Err(e))) => {
                        eprintln!(
                            "relay watch {}: {e}; polling relay v2 until re-probe",
                            links[idx].peer_id
                        );
                        links[idx].poll_only_until = Some(Instant::now() + WATCH_REPROBE_INTERVAL);
                    }
                    Some((idx, Ok(page)))
                        if !page.reset && page.head <= links[idx].relay_cursor.after =>
                    {
                        tokio::time::sleep(WATCH_EMPTY_BACKOFF).await;
                    }
                    _ => {}
                }
            }
        }
    }
}
