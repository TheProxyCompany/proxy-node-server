//! # proxy-node-server
//!
//! The open mesh/sync layer of the Proxy network: a signed, HLC-ordered op-log
//! replication engine with pluggable stores.

pub mod address;
#[cfg(feature = "discovery")]
pub mod discovery;
pub mod durable;
pub mod error;
pub mod file_store;
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
pub mod ports;
pub mod pull;
pub mod registry;
pub mod row_op;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod store;
pub mod thread_sources;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteError;
pub mod transport;

pub use error::{DurabilityError, HlcError, IdentityError, NodeError, OpError, ReplayError};
pub use file_store::{FileMutation, FileStoreOp, RowAuthority, sha256_hex, should_emit_sweep_file};
pub use hlc::{DEFAULT_MAX_DELTA, Hlc, NodeClock};
pub use identity::{DeviceId, DeviceIdentity};
pub use kv::{KvOp, KvStore};
pub use log::{
    LogSource, OpLog, RelayLogEntry, RelayLogPage, RelayStreamState, apply_range, replay,
};
pub use op::{ENVELOPE_VERSION, MAX_STORE_ID_LEN, OpBody, OpId, OrderKey, SignedOp, StoreId};
pub use pull::{
    CoverageVector, MAX_PULL_REQUEST_BYTES, MAX_PULL_RESPONSE_BYTES, MAX_REQUEST_SKEW_MS,
    OriginHead, PAGE_LIMIT_MAX, PULL_PAGE_BYTE_BUDGET, PULL_PAGE_LIMIT_MAX, PULL_PAGE_STORE_ID,
    PULL_PATH, PULL_REQUEST_STORE_ID, PULL_RESPONSE_STORE_ID, PULL_VERSION, PullPage, PullPhase,
    PullRequest, Resume,
};
#[cfg(feature = "daemon")]
pub use pull::{seal_pull_page, sign_pull_request, verify_pull_page, verify_pull_request};
pub use registry::{DeviceBook, DeviceRegistry};
pub use row_op::{
    Column, KeyField, Mutation, ORIGIN_LOCAL, ORIGIN_REMOTE, ProxyDbOp, RowOp, STORE_ID, Scalar,
    is_valid_ident, row_pk_of, store_id as row_store_id,
};
pub use store::{OpContext, Store};
pub use transport::{Cursor, PeerId};

#[cfg(feature = "pull-http")]
pub use error::TransportError;
#[cfg(feature = "pull-http")]
pub use net::{
    ApplyMode, DEFAULT_MAX_PARKED_WATCHES, DEFAULT_PULL_LIMIT, DISCOVERY_RESCAN_INTERVAL,
    DeviceEntry, DevicesResp, HeadPublisher, HeadWatch, HttpPullSource, IdentityResp,
    MESH_AUDIT_ENV, MESH_PEERS_ENV, MeshPullHost, MeshPullSocket, NEWEST_FIRST_PREVIEW_GAP,
    OpLogPullSocket, PULL_FALLBACK_INTERVAL, PULL_NO_PROGRESS_LIMIT, PullAdmission, PullHandler,
    PullOutcome, PullProgress, PullResponse, PullStorage, REGISTER_RETRY_BACKOFF,
    RELAY_PROTOCOL_VERSION, RelayCursor, RelayOp, RelayPage, RelayResponse, RelaySyncOutcome,
    RelayWireEntry, ServeState, TRELLIS_SWEEP_INTERVAL, WATCH_DEFAULT_WAIT, WATCH_EMPTY_BACKOFF,
    WATCH_MAX_WAIT, WATCH_REPROBE_INTERVAL, admit_pull_ack, apply_pull_page,
    authenticate_pull_request, build_keyed_channel, build_pull_page, classify_pull_request_error,
    decode_epoch, decode_order_key, decode_page_op, drain_pull_pages, encode_order_key,
    encode_origin_rows, endpoint_has_confidential_transport, inflated_claims, is_cgnat_ip,
    is_loopback_host, keyed_resume, learn_attested_devices, learn_devices, load_cursor,
    load_peer_keys, load_relay_caller_keys, load_relay_cursor, parse_mesh_peers,
    parse_mesh_peers_from, persist_pull_reset, preview_head_window, preview_resume_after,
    pull_http_client, pull_needs_reset, pull_progress, pull_router, register_peer,
    register_peer_with_key, relay_router, reset_pull_page, router, save_cursor, save_peer_keys,
    save_relay_caller_keys, save_relay_cursor, sweep_store, sync_once, sync_once_with,
    sync_relay_once, unix_ms, validate_pull_reset,
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
    fn every_source_file_is_under_eight_hundred_lines() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        assert!(!files.is_empty());
        for path in files {
            let content = std::fs::read_to_string(&path).expect("read rs file");
            let lines = content.lines().count();
            assert!(
                lines < 800,
                "{} has {} lines (must be strictly < 800)",
                path.display(),
                lines
            );
        }
    }
}

#[cfg(feature = "pull-http")]
pub mod tunnel;

#[cfg(feature = "pull-http")]
pub mod address_client;
#[cfg(feature = "daemon")]
pub mod roster;
#[cfg(feature = "daemon")]
pub mod scope;
pub mod usage;

#[cfg(feature = "pull-http")]
pub mod address_web;
#[cfg(feature = "daemon")]
pub mod mcp_protocol;
