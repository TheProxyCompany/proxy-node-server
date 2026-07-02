//! # proxy-node-server
//!
//! The open mesh/sync layer of the Proxy network: a signed, HLC-ordered op-log
//! replication engine with pluggable stores.
//!
//! Phase 0 ships the foundation:
//!
//! - [`identity`]: P-256 device identities and stable device ids.
//! - [`hlc`]: a hybrid logical clock for global op ordering.
//! - [`op`]: the signed, content-addressed replication envelope.
//! - [`store`]: the semantics-free [`store::Store`] contract.
//! - [`log`]: the op-log engine (append + dedup + HLC-ordered replay).
//! - [`kv`]: a toy in-memory KV store, the reference implementor.
//! - [`transport`]: a reserved phase-1 seam (types only, no networking).
//!
//! The library is the primary artifact; the `pnsd` reference daemon builds only
//! under the `daemon` feature.

pub mod error;
pub mod hlc;
pub mod identity;
pub mod kv;
pub mod log;
pub mod op;
pub mod store;
pub mod transport;

pub use error::{HlcError, IdentityError, OpError, ReplayError};
pub use hlc::{Hlc, HlcClock, MAX_DRIFT_MICROS};
pub use identity::{DeviceId, DeviceIdentity};
pub use kv::{KvOp, KvStore};
pub use log::{OpLog, replay};
pub use op::{ENVELOPE_VERSION, MAX_STORE_ID_LEN, OpBody, OpId, OrderKey, SignedOp, StoreId};
pub use store::{OpContext, Store};
pub use transport::{Cursor, PeerId, PullSource};
