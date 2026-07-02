//! The `Store` trait: the semantics-free contract between the op-log engine and
//! a replicated store. The engine hands ops to `apply` in HLC total order and
//! never inspects `payload`. Conflict repair — buffering an edge that arrives
//! before its node, resolving delete-vs-attach — is entirely the implementor's
//! job.

use crate::hlc::Hlc;
use crate::identity::DeviceId;
use crate::op::{OpId, OrderKey, StoreId};

/// Per-op context handed to [`Store::apply`]. Carries everything the store needs
/// to implement idempotency and repair: the content id (dedup key), the global
/// order key, and the HLC/device the op was stamped with.
#[derive(Clone, Copy, Debug)]
pub struct OpContext<'a> {
    pub op_id: OpId,
    pub order_key: OrderKey,
    pub hlc: Hlc,
    pub device: &'a DeviceId,
}

/// A replicated store adapter.
pub trait Store {
    /// The store's native operation type.
    type Op;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Namespace this store claims in the shared op-log.
    fn store_id(&self) -> StoreId;

    /// Encode a native op into the envelope's opaque payload.
    fn encode(&self, op: &Self::Op) -> Result<Vec<u8>, Self::Error>;

    /// Decode payload bytes back into a native op.
    fn decode(&self, payload: &[u8]) -> Result<Self::Op, Self::Error>;

    /// Apply one op. The engine guarantees a global total order across all
    /// devices; it does not guarantee local causal validity. `ctx` carries the
    /// op id, order key, HLC, and device so the store can implement its own
    /// repair and idempotency.
    fn apply(&mut self, ctx: OpContext<'_>, op: Self::Op) -> Result<(), Self::Error>;
}
