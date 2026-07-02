//! Toy in-memory key/value store — the reference `Store` implementor. Ops are
//! last-write-wins by HLC order; since the engine replays in HLC total order,
//! `apply` just mutates the map.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::op::StoreId;
use crate::store::{OpContext, Store};

/// The namespace this store claims in a shared op-log.
pub fn kv_store_id() -> StoreId {
    StoreId::new("kv").expect("kv store id is valid")
}

/// A native key/value mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KvOp {
    Put { key: String, value: Vec<u8> },
    Delete { key: String },
}

#[derive(Debug, Error)]
pub enum KvError {
    #[error("kv payload codec error: {0}")]
    Codec(#[from] postcard::Error),
}

/// A last-write-wins key/value map.
#[derive(Default)]
pub struct KvStore {
    data: BTreeMap<String, Vec<u8>>,
}

impl KvStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.data.get(key).map(Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Store for KvStore {
    type Op = KvOp;
    type Error = KvError;

    fn store_id(&self) -> StoreId {
        kv_store_id()
    }

    fn encode(&self, op: &Self::Op) -> Result<Vec<u8>, Self::Error> {
        Ok(postcard::to_allocvec(op)?)
    }

    fn decode(&self, payload: &[u8]) -> Result<Self::Op, Self::Error> {
        Ok(postcard::from_bytes(payload)?)
    }

    fn apply(&mut self, _ctx: OpContext<'_>, op: Self::Op) -> Result<(), Self::Error> {
        match op {
            KvOp::Put { key, value } => {
                self.data.insert(key, value);
            }
            KvOp::Delete { key } => {
                self.data.remove(&key);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::identity::DeviceIdentity;
    use crate::log::{OpLog, replay};
    use crate::op::{ENVELOPE_VERSION, OpBody, SignedOp};

    fn seal_kv(id: &DeviceIdentity, store: &KvStore, hlc: Hlc, op: &KvOp) -> SignedOp {
        let payload = store.encode(op).unwrap();
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc,
            device: id.device_id(),
            store: kv_store_id(),
            payload,
        };
        SignedOp::seal(body, id).unwrap()
    }

    #[test]
    fn encode_decode_round_trip() {
        let store = KvStore::new();
        let op = KvOp::Put {
            key: "a".into(),
            value: vec![9, 9, 9],
        };
        let bytes = store.encode(&op).unwrap();
        assert_eq!(store.decode(&bytes).unwrap(), op);
    }

    #[test]
    fn replay_applies_in_hlc_order() {
        let id = DeviceIdentity::generate();
        let template = KvStore::new();
        let mut log = OpLog::new();

        // Deliberately append out of order; the engine must replay by HLC.
        log.append(seal_kv(
            &id,
            &template,
            Hlc(30),
            &KvOp::Put {
                key: "k".into(),
                value: b"final".to_vec(),
            },
        ));
        log.append(seal_kv(
            &id,
            &template,
            Hlc(10),
            &KvOp::Put {
                key: "k".into(),
                value: b"first".to_vec(),
            },
        ));
        log.append(seal_kv(
            &id,
            &template,
            Hlc(20),
            &KvOp::Put {
                key: "k".into(),
                value: b"middle".to_vec(),
            },
        ));
        log.append(seal_kv(
            &id,
            &template,
            Hlc(25),
            &KvOp::Put {
                key: "gone".into(),
                value: b"x".to_vec(),
            },
        ));
        log.append(seal_kv(
            &id,
            &template,
            Hlc(26),
            &KvOp::Delete { key: "gone".into() },
        ));

        let mut store = KvStore::new();
        replay(&log, &mut store).unwrap();

        // Highest-HLC write to "k" wins; the delete after the put removes "gone".
        assert_eq!(store.get("k"), Some(&b"final"[..]));
        assert_eq!(store.get("gone"), None);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn replay_is_deterministic_across_two_stores() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        let template = KvStore::new();
        let mut log = OpLog::new();

        // Same HLC wall, two devices: order_key ties break on device id, so both
        // replicas converge to the same value.
        log.append(seal_kv(
            &a,
            &template,
            Hlc(5),
            &KvOp::Put {
                key: "x".into(),
                value: b"from-a".to_vec(),
            },
        ));
        log.append(seal_kv(
            &b,
            &template,
            Hlc(5),
            &KvOp::Put {
                key: "x".into(),
                value: b"from-b".to_vec(),
            },
        ));

        let mut s1 = KvStore::new();
        let mut s2 = KvStore::new();
        replay(&log, &mut s1).unwrap();
        replay(&log, &mut s2).unwrap();
        assert_eq!(s1.get("x"), s2.get("x"));
    }
}
