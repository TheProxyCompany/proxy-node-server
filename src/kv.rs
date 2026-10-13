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
