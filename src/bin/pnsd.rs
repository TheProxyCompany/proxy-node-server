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
        /// Seconds between pull rounds.
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
            pull_interval,
        }) => serve::run(resolve_data_dir(data_dir), listen, peers, pull_interval),
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
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use proxy_node_server::{
        DeviceIdentity, DeviceRegistry, HttpPullSource, KvStore, NodeClock, OpLog, OplogWriter,
        ServeState, learn_devices, load_cursor, load_peer_keys, register_peer, replay,
        replay_oplog_file, router, save_cursor, save_peer_keys, sync_once,
    };

    use super::{KEY_FILE, OPLOG_FILE, read_scalar};

    pub fn run(
        data_dir: PathBuf,
        listen: SocketAddr,
        peers: Vec<String>,
        pull_interval: u64,
    ) -> Result<(), String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
        rt.block_on(serve(data_dir, listen, peers, pull_interval))
    }

    async fn serve(
        data_dir: PathBuf,
        listen: SocketAddr,
        peers: Vec<String>,
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

        let app = router(ServeState::new(
            identity.clone(),
            log.clone(),
            registry.clone(),
        ));
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        println!("pnsd serving {} on {listen}", identity.device_id());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("server exited: {e}");
            }
        });

        let mut targets = Vec::new();
        let mut learned_keys = false;
        for base in peers {
            let source = HttpPullSource::new(&base);
            match register_peer(&source, &registry).await {
                Ok((peer_id, newly_added)) => {
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
                    // Gossip: adopt every device this peer vouches for so ops it
                    // relays from third parties verify. Same durability rule —
                    // persist before pulling, roll back exactly what we added on
                    // a failed save so no un-persisted key ever verifies an op.
                    match learn_devices(&source, &registry).await {
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
                    let cursor = load_cursor(&data_dir, &peer_id);
                    println!("peer {peer_id} at {base}");
                    targets.push((source, peer_id, cursor));
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
            }
        }

        let interval = Duration::from_secs(pull_interval);
        loop {
            for (source, peer_id, cursor) in &mut targets {
                let before = *cursor;
                let result = sync_once(
                    source,
                    &registry,
                    &clock,
                    &log,
                    &store,
                    cursor,
                    Some(&writer),
                )
                .await;
                // The cursor only ever advances over ops the op-log has already
                // fsynced, so persisting it is safe whether the batch fully
                // completed or aborted partway on a bad op — it never points
                // past durable ops.
                if *cursor != before {
                    if let Err(e) = save_cursor(&data_dir, peer_id, *cursor) {
                        eprintln!("save cursor {peer_id}: {e}");
                    }
                }
                match result {
                    Ok(n) if n > 0 => println!("pulled {n} op(s) from {peer_id}"),
                    Ok(_) => {}
                    Err(e) => eprintln!("pull {peer_id}: {e}"),
                }
            }
            tokio::time::sleep(interval).await;
        }
    }
}
