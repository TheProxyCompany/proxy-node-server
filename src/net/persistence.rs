//! Durable persistence for pull cursors and peer verifying keys.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::RelayCursorV2;
use crate::identity::DeviceId;
use crate::op::OrderKey;
use crate::registry::DeviceRegistry;

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

/// Persist a peer's cursor durably via temp-file fsync, rename, and parent
/// directory fsync.
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

fn relay_cursor_path(data_dir: &Path, peer: &DeviceId) -> PathBuf {
    data_dir
        .join("cursors")
        .join(format!("{}.relay-v2.cursor", peer.to_hex()))
}

/// Load a peer's persisted `(epoch, relay sequence)` cursor.
pub fn load_relay_cursor(data_dir: &Path, peer: &DeviceId) -> RelayCursorV2 {
    let Ok(bytes) = std::fs::read(relay_cursor_path(data_dir, peer)) else {
        return RelayCursorV2::START;
    };
    if bytes.len() != 40 {
        return RelayCursorV2::START;
    }
    let mut epoch = [0u8; 32];
    epoch.copy_from_slice(&bytes[..32]);
    let mut after = [0u8; 8];
    after.copy_from_slice(&bytes[32..]);
    let after = u64::from_be_bytes(after);
    if epoch == [0u8; 32] && after != 0 {
        return RelayCursorV2::START;
    }
    RelayCursorV2 { epoch, after }
}

/// Durably persist a relay-v2 cursor in a file distinct from the v1 semantic
/// cursor.
pub fn save_relay_cursor(
    data_dir: &Path,
    peer: &DeviceId,
    cursor: RelayCursorV2,
) -> std::io::Result<()> {
    let path = relay_cursor_path(data_dir, peer);
    let dir = path
        .parent()
        .expect("relay cursor path always has a `cursors` parent");
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("cursor.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&cursor.epoch)?;
        file.write_all(&cursor.after.to_be_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    fsync_dir(dir)
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

fn peers_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peers.bin")
}

fn relay_callers_path(data_dir: &Path) -> PathBuf {
    data_dir.join("relay-callers.bin")
}

/// Load persisted peer keys into the registry. Returns how many registered.
pub fn load_peer_keys(data_dir: &Path, registry: &mut DeviceRegistry) -> usize {
    load_keys(&peers_path(data_dir), registry)
}

/// Load the direct relay-caller allowlist.
pub fn load_relay_caller_keys(data_dir: &Path, registry: &mut DeviceRegistry) -> usize {
    load_keys(&relay_callers_path(data_dir), registry)
}

fn load_keys(path: &Path, registry: &mut DeviceRegistry) -> usize {
    let Ok(bytes) = std::fs::read(path) else {
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
/// [`save_cursor`].
pub fn save_peer_keys(data_dir: &Path, registry: &DeviceRegistry) -> std::io::Result<()> {
    save_keys(&peers_path(data_dir), registry)
}

/// Persist only direct relay callers, never transitive `/devices` entries.
pub fn save_relay_caller_keys(data_dir: &Path, registry: &DeviceRegistry) -> std::io::Result<()> {
    save_keys(&relay_callers_path(data_dir), registry)
}

fn save_keys(path: &Path, registry: &DeviceRegistry) -> std::io::Result<()> {
    let keys: Vec<Vec<u8>> = registry.sec1_keys().iter().map(|k| k.to_vec()).collect();
    let bytes = postcard::to_allocvec(&keys)
        .map_err(|e| std::io::Error::other(format!("encode peer keys: {e}")))?;
    let dir = path.parent().expect("key path always has a parent");
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("bin.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    fsync_dir(dir)
}
