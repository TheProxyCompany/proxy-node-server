//! # proxy-node-server
//!
//! The open mesh/sync layer of the Proxy network: a signed, HLC-ordered op-log
//! replication engine with pluggable stores.
//!
//! - [`identity`]: P-256 device identities and stable device ids.
//! - [`hlc`]: a hybrid logical clock ([`uhlc`]-backed) for global op ordering.
//! - [`op`]: the signed, content-addressed replication envelope.
//! - [`store`]: the semantics-free [`store::Store`] contract.
//! - [`log`]: the op-log engine (append + dedup + HLC-ordered replay).
//! - [`kv`]: a toy in-memory KV store, the reference implementor.
//! - [`registry`]: device-id → verifying-key map used to verify pulled ops.
//! - [`durable`]: append-only op-log durability file for the reference daemon.
//! - [`transport`]: the [`transport::PullSource`] seam.
//! - [`net`] (feature `pull-http`): the HTTP pull server, client, and pull loop.
//!
//! The library is the primary artifact; the `pnsd` reference daemon builds under
//! the `daemon` feature, and networked replication under `pull-http`.

pub mod durable;
pub mod error;
pub mod hlc;
pub mod identity;
pub mod kv;
pub mod log;
#[cfg(feature = "pull-http")]
pub mod net;
pub mod op;
pub mod registry;
pub mod store;
pub mod transport;

pub use error::{DurabilityError, HlcError, IdentityError, OpError, ReplayError};
pub use hlc::{DEFAULT_MAX_DELTA, Hlc, NodeClock};
pub use identity::{DeviceId, DeviceIdentity};
pub use kv::{KvOp, KvStore};
pub use log::{OpLog, replay};
pub use op::{ENVELOPE_VERSION, MAX_STORE_ID_LEN, OpBody, OpId, OrderKey, SignedOp, StoreId};
pub use registry::DeviceRegistry;
pub use store::{OpContext, Store};
pub use transport::{Cursor, PeerId};

#[cfg(feature = "pull-http")]
pub use error::TransportError;
#[cfg(feature = "pull-http")]
pub use net::{
    DEFAULT_PULL_LIMIT, HttpPullSource, IdentityResp, PullResponse, ServeState, load_cursor,
    load_peer_keys, register_peer, router, save_cursor, save_peer_keys, sync_once,
};
#[cfg(feature = "pull-http")]
pub use transport::PullSource;

pub use durable::{OplogWriter, replay_oplog_file};
