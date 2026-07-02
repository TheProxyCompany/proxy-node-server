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

//! - [`discovery`] (feature `discovery`): provider-agnostic presence/transport
//!   seams, with mDNS and Tailscale providers behind their own features.
//! - [`harness`] (feature `harness`): in-process multi-daemon test/perf harness.

#[cfg(feature = "discovery")]
pub mod discovery;
pub mod durable;
pub mod error;
#[cfg(feature = "harness")]
pub mod harness;
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
pub use log::{LogSource, OpLog, apply_range, replay};
pub use op::{ENVELOPE_VERSION, MAX_STORE_ID_LEN, OpBody, OpId, OrderKey, SignedOp, StoreId};
pub use registry::{DeviceBook, DeviceRegistry};
pub use store::{OpContext, Store};
pub use transport::{Cursor, PeerId};

#[cfg(feature = "pull-http")]
pub use error::TransportError;
#[cfg(feature = "pull-http")]
pub use net::{
    ApplyMode, DEFAULT_PULL_LIMIT, DeviceEntry, DevicesResp, HttpPullSource, IdentityResp,
    PullResponse, ServeState, learn_devices, load_cursor, load_peer_keys, register_peer, router,
    save_cursor, save_peer_keys, sync_once, sync_once_with,
};
#[cfg(feature = "pull-http")]
pub use transport::PullSource;

#[cfg(feature = "discovery")]
pub use discovery::{HttpTransport, LocalAdvert, PeerInfo, PeerTransport, PresenceProvider};

pub use durable::{OplogWriter, replay_oplog_file};
