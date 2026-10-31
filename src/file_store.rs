//! File and directory store synchronization primitives (`AgentStore`, `PartyStore`)
//! implementing the [`crate::store::Store`] pattern.
//!
//! Ownership and convergence derive directly from authenticated op-log heads
//! (`RowAuthority`) and content SHA-256 digests — never from hidden `.mesh`
//! dotfiles on disk.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Who the replicated op-log heads say authored a synced folder or file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RowAuthority {
    /// The newest authenticated op was minted on this device (or names its identity).
    Local,
    /// Authenticated ops exist and every newest one names another device.
    Remote,
}

/// Mutation payload for a file-backed [`crate::store::Store`] (`PartyStore`, `AgentStore`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMutation {
    Upsert { content: Vec<u8>, mode: u32 },
    Delete,
}

/// Operation for a directory/file-backed [`crate::store::Store`] (`PartyStore`, `AgentStore`),
/// keyed by `(entity_id, relative_path)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStoreOp {
    pub entity_id: String,
    pub path: String,
    pub mutation: FileMutation,
}

impl FileStoreOp {
    pub fn row_pk(&self) -> String {
        crate::row_op::row_pk_of(&[("id", &self.entity_id), ("path", &self.path)])
    }

    pub fn encode_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn decode_bytes(payload: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(payload)
    }
}

/// Compute the lowercase hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in &digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Whether a local file scan should emit a new op for `(on_disk_bytes, stored_bytes)`:
/// returns `false` when the bytes already match the stored op-log image or when
/// the row's newest authenticated op was authored by another device during a
/// periodic background sweep.
pub fn should_emit_sweep_file(
    on_disk_bytes: &[u8],
    stored_bytes: Option<&[u8]>,
    authority: Option<RowAuthority>,
) -> bool {
    if matches!(authority, Some(RowAuthority::Remote)) {
        return false;
    }
    match stored_bytes {
        Some(stored) => stored != on_disk_bytes,
        None => true,
    }
}
