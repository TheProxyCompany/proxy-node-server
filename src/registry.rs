//! Device registry: maps a `DeviceId` to the verifying key needed to check ops
//! it stamped. A peer's op-log carries ops from many devices (its own, the
//! puller's echoed back, and any it replicated transitively), so verification
//! resolves the key per op from this registry rather than assuming one peer key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p256::ecdsa::VerifyingKey;

use crate::error::IdentityError;
use crate::identity::{DeviceId, DeviceIdentity};

/// Known device verifying keys, keyed by derived device id.
#[derive(Default)]
pub struct DeviceRegistry {
    keys: HashMap<DeviceId, VerifyingKey>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a verifying key, returning the device id it derives.
    pub fn insert_key(&mut self, key: VerifyingKey) -> DeviceId {
        let id = DeviceIdentity::device_id_of_key(&key);
        self.keys.insert(id, key);
        id
    }

    /// Register a device from its advertised compressed SEC1 public key.
    pub fn insert_sec1(&mut self, sec1: &[u8; 33]) -> Result<DeviceId, IdentityError> {
        let key =
            VerifyingKey::from_sec1_bytes(sec1).map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(self.insert_key(key))
    }

    pub fn key_for(&self, id: &DeviceId) -> Option<&VerifyingKey> {
        self.keys.get(id)
    }

    /// Every registered key as compressed SEC1 bytes, for persistence.
    pub fn sec1_keys(&self) -> Vec<[u8; 33]> {
        self.keys
            .values()
            .map(crate::identity::sec1_compressed)
            .collect()
    }

    /// Every known device as `(device_id, compressed SEC1 key)` — the set the
    /// `/devices` route gossips so a puller can verify ops from devices it has
    /// never contacted directly (D11 transitive key propagation).
    pub fn entries(&self) -> Vec<(DeviceId, [u8; 33])> {
        self.keys
            .iter()
            .map(|(id, key)| (*id, crate::identity::sec1_compressed(key)))
            .collect()
    }

    pub fn contains(&self, id: &DeviceId) -> bool {
        self.keys.contains_key(id)
    }

    /// Remove a device's key. Used to evict a key that could not be durably
    /// persisted: a key that verification can see but the next startup cannot
    /// reload would let cursors advance past ops that startup replay will then
    /// skip as unknown-device.
    pub fn remove(&mut self, id: &DeviceId) {
        self.keys.remove(id);
    }
}

/// Read-only source of the trusted device set for the `/devices` route. The
/// reference registry serves it behind an `Arc<Mutex<..>>`; Grand Central
/// implements it over the `devices` proxy.db table so [`crate::net::router`]
/// gossips keys without owning the storage. `Clone` because it lives in axum
/// state.
pub trait DeviceBook: Clone + Send + Sync + 'static {
    /// Every trusted device as `(device_id, compressed SEC1 key)`.
    fn known_devices(&self) -> Vec<(DeviceId, [u8; 33])>;
}

impl DeviceBook for Arc<Mutex<DeviceRegistry>> {
    fn known_devices(&self) -> Vec<(DeviceId, [u8; 33])> {
        self.lock().expect("registry mutex poisoned").entries()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_resolve() {
        let id = DeviceIdentity::generate();
        let mut reg = DeviceRegistry::new();
        assert!(!reg.contains(&id.device_id()));

        let registered = reg.insert_sec1(&id.public_key_sec1()).unwrap();
        assert_eq!(registered, id.device_id());
        assert!(reg.contains(&id.device_id()));
        assert_eq!(reg.key_for(&id.device_id()), Some(id.verifying_key()));

        let other = DeviceIdentity::generate();
        assert_eq!(reg.key_for(&other.device_id()), None);
    }

    #[test]
    fn insert_sec1_rejects_junk() {
        let mut reg = DeviceRegistry::new();
        assert!(reg.insert_sec1(&[0u8; 33]).is_err());
    }
}
