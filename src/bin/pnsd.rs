//! `pnsd` — the phase-0 reference daemon. No serving, no networking: it proves
//! device-key generation, key-import parity with the Swift app, and the derived
//! device id.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use proxy_node_server::{DeviceIdentity, ENVELOPE_VERSION};

const KEY_FILE: &str = "device.key";
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
