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
//! - [`pull_v3`]: Pull Protocol v3 wire types and signed envelope primitives.
//! - [`net`] (feature `pull-http`): the HTTP pull server, client, and pull loop.
//! - [`oauth`]: the node as the OAuth authorization server for its own
//!   address, so a client connects with a click in Proxy, not a pasted bearer.
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
pub mod oauth;
pub mod op;
pub mod pull_v3;
pub mod registry;
pub mod store;
pub mod transport;

pub use error::{DurabilityError, HlcError, IdentityError, OpError, ReplayError};
pub use hlc::{DEFAULT_MAX_DELTA, Hlc, NodeClock};
pub use identity::{DeviceId, DeviceIdentity};
pub use kv::{KvOp, KvStore};
pub use log::{
    LogSource, OpLog, RelayLogEntry, RelayLogPage, RelayStreamState, apply_range, replay,
};
pub use op::{ENVELOPE_VERSION, MAX_STORE_ID_LEN, OpBody, OpId, OrderKey, SignedOp, StoreId};
pub use pull_v3::{
    MAX_REQUEST_SKEW_MS, MAX_V3_REQUEST_BYTES, MAX_V3_RESPONSE_BYTES, OriginHeadV3, PAGE_LIMIT_MAX,
    PULL_PAGE_STORE_ID, PULL_PATH, PULL_REQUEST_STORE_ID, PULL_RESPONSE_STORE_ID, PULL_V3_VERSION,
    PullPageV3, PullPhase, PullRequestV3, ResumeV3, V3_PAGE_BYTE_BUDGET, V3_PAGE_LIMIT_MAX,
};
#[cfg(feature = "daemon")]
pub use pull_v3::{
    seal_pull_page_v3, sign_pull_request_v3, verify_pull_page_v3, verify_pull_request_v3,
};
pub use registry::{DeviceBook, DeviceRegistry};
pub use store::{OpContext, Store};
pub use transport::{Cursor, PeerId};

#[cfg(feature = "pull-http")]
pub use error::TransportError;
#[cfg(feature = "pull-http")]
pub use net::{
    ApplyMode, DEFAULT_MAX_PARKED_WATCHES, DEFAULT_PULL_LIMIT, DeviceEntry, DevicesResp,
    HeadPublisher, HeadWatch, HttpPullSource, IdentityResp, PullResponse, RELAY_PROTOCOL_VERSION,
    RelayCursorV2, RelayOpV2, RelayPageV2, RelayResponseV2, RelaySyncOutcome, RelayWireEntryV2,
    ServeState, WATCH_DEFAULT_WAIT, WATCH_EMPTY_BACKOFF, WATCH_MAX_WAIT, learn_attested_devices,
    learn_devices, load_cursor, load_peer_keys, load_relay_caller_keys, load_relay_cursor,
    register_peer, register_peer_with_key, relay_router, router, save_cursor, save_peer_keys,
    save_relay_caller_keys, save_relay_cursor, sync_once, sync_once_with, sync_relay_once_v2,
};
#[cfg(feature = "pull-http")]
pub use transport::PullSource;

#[cfg(feature = "discovery")]
pub use discovery::{HttpTransport, LocalAdvert, PeerInfo, PeerTransport, PresenceProvider};

pub use durable::{OplogWriter, replay_oplog_file};

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("read src dir");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn every_source_file_is_under_one_thousand_lines() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        assert!(!files.is_empty());
        for path in files {
            let content = std::fs::read_to_string(&path).expect("read rs file");
            let lines = content.lines().count();
            assert!(
                lines < 1_000,
                "{} has {} lines (must be strictly < 1,000)",
                path.display(),
                lines
            );
        }
    }
}
