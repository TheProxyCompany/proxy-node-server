//! Unified HTTP pull & sync surface (feature `pull-http`): v1 semantic pull,
//! Relay insertion-ordered stream, Pull two-channel sync, the
//! [`MeshPullSocket`] ("Female Socket") storage trait, and peer transport
//! confidentiality policy.

mod client;
pub mod gate;
mod persistence;
mod policy;
mod pull_client;
mod pull_server;
mod relay;
mod server;
mod socket;
mod sync;
mod watch;

#[cfg(test)]
mod tests_pull;
#[cfg(test)]
mod tests_relay;
#[cfg(test)]
mod tests_support;
#[cfg(test)]
mod tests_watch;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::decode_hex;
use crate::op::{OrderKey, SignedOp};

pub use crate::pull::{
    CoverageVector, MAX_PULL_REQUEST_BYTES, MAX_PULL_RESPONSE_BYTES, MAX_REQUEST_SKEW_MS,
    OriginHead, PAGE_LIMIT_MAX, PULL_PAGE_BYTE_BUDGET, PULL_PAGE_LIMIT_MAX, PULL_PAGE_STORE_ID,
    PULL_PATH, PULL_REQUEST_STORE_ID, PULL_RESPONSE_STORE_ID, PULL_VERSION, PullPage, PullPhase,
    PullRequest, Resume, seal_pull_page, sign_pull_request, verify_pull_page, verify_pull_request,
};
pub use client::HttpPullSource;
pub use persistence::{
    load_cursor, load_peer_keys, load_relay_caller_keys, load_relay_cursor, save_cursor,
    save_peer_keys, save_relay_caller_keys, save_relay_cursor,
};
pub use policy::{
    MESH_AUDIT_ENV, MESH_PEERS_ENV, endpoint_has_confidential_transport, is_cgnat_ip,
    is_loopback_host, parse_mesh_peers, parse_mesh_peers_from,
};
pub use pull_client::{
    DISCOVERY_RESCAN_INTERVAL, NEWEST_FIRST_PREVIEW_GAP, PULL_FALLBACK_INTERVAL,
    PULL_NO_PROGRESS_LIMIT, PullOutcome, PullProgress, REGISTER_RETRY_BACKOFF,
    TRELLIS_SWEEP_INTERVAL, WATCH_REPROBE_INTERVAL, apply_pull_page, decode_epoch,
    decode_order_key, decode_page_op, drain_pull_pages, inflated_claims, persist_pull_reset,
    preview_head_window, preview_resume_after, pull_http_client, pull_progress, sweep_store,
    unix_ms, validate_pull_reset,
};
pub use pull_server::{
    PullHandler, admit_pull_ack, authenticate_pull_request, build_keyed_channel, build_pull_page,
    classify_pull_request_error, encode_origin_rows, keyed_resume, pull_needs_reset, pull_router,
    reset_pull_page,
};
pub use server::{ServeState, relay_router, router};
pub use socket::{MeshPullHost, MeshPullSocket, OpLogPullSocket, PullAdmission, PullStorage};
pub use sync::{
    ApplyMode, RelaySyncOutcome, learn_attested_devices, learn_devices, register_peer,
    register_peer_with_key, sync_once, sync_once_with, sync_relay_once,
};
pub use watch::{HeadPublisher, HeadWatch};

/// Default cap on the number of ops returned by one `/ops` page.
pub const DEFAULT_PULL_LIMIT: u16 = 512;

/// Default per-request timeout for a pull/probe. Bounds a single request so one
/// blackholed peer (e.g. a stale tailnet IP) can never hang a browse tick or a
/// pull loop indefinitely; `reqwest::Client` has no timeout by default.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Default server-hold for a `/watch` long-poll: how long a parked handler waits
/// for the head to move before returning the unchanged head.
pub const WATCH_DEFAULT_WAIT: Duration = Duration::from_millis(25_000);

/// Client-side backoff after a `/watch` that returns `Ok` with a head at or
/// behind the caller's cursor (e.g. an over-capacity server that sheds the park
/// via [`ServeState::with_watch_limit`]).
pub const WATCH_EMPTY_BACKOFF: Duration = Duration::from_millis(500);

/// Hard cap on the `/watch` hold, kept under intermediary idle limits.
pub const WATCH_MAX_WAIT: Duration = Duration::from_millis(50_000);

/// Default cap on concurrently parked `/watch` long-polls.
pub const DEFAULT_MAX_PARKED_WATCHES: usize = 64;

/// Version carried inside every relay-local v2 response body.
pub const RELAY_PROTOCOL_VERSION: u8 = 2;

/// `/identity` response: what a puller needs to verify this peer's ops.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResp {
    pub device_id: [u8; 32],
    pub public_key_sec1: Vec<u8>,
}

/// `/ops` response: a page of envelope bytes plus the resume cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullResponse {
    /// Each entry is one [`SignedOp::to_bytes`] envelope, in total order.
    pub ops: Vec<Vec<u8>>,
    /// Highest order key returned (72-byte [`OrderKey`] wire form), or the echoed
    /// `since` when the page is empty.
    pub next: Vec<u8>,
}

/// Resume point for the insertion-ordered relay-local v2 stream. The all-zero
/// epoch is the explicit first-contact sentinel; a successful response replaces
/// it with the server's authenticated stream epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayCursor {
    pub epoch: [u8; 32],
    pub after: u64,
}

impl RelayCursor {
    pub const START: Self = Self {
        epoch: [0; 32],
        after: 0,
    };

    pub const fn new(epoch: [u8; 32], after: u64) -> Self {
        Self { epoch, after }
    }
}

impl Default for RelayCursor {
    fn default() -> Self {
        Self::START
    }
}

/// Wire entry authenticated inside a [`RelayResponse`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayWireEntry {
    pub seq: u64,
    pub envelope: Vec<u8>,
}

/// Exact postcard body returned by all three relay-local routes. `/relay/head`
/// and `/relay/watch` carry no entries; `/relay/ops` carries a bounded page.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayResponse {
    pub v: u8,
    pub epoch: [u8; 32],
    pub head: u64,
    pub floor: u64,
    /// Last sequence actually carried by an ops page, or the request's `after`
    /// for a head/watch response. A reset instead returns `floor`.
    pub next: u64,
    pub reset: bool,
    pub entries: Vec<RelayWireEntry>,
}

/// One verified and decoded operation from a relay-local page.
#[derive(Clone, Debug)]
pub struct RelayOp {
    pub seq: u64,
    pub op: SignedOp,
}

/// Authenticated, validated, and envelope-decoded v2 response returned to
/// callers. `reset` instructs the caller to replace its cursor with
/// [`RelayPage::cursor`] before requesting again.
#[derive(Clone, Debug)]
pub struct RelayPage {
    pub epoch: [u8; 32],
    pub head: u64,
    pub floor: u64,
    pub next: u64,
    pub reset: bool,
    pub entries: Vec<RelayOp>,
}

impl RelayPage {
    /// Safe continuation cursor. Head/watch responses preserve the caller's
    /// `after`, so observing available work never skips entries not yet pulled.
    pub fn cursor(&self) -> RelayCursor {
        RelayCursor {
            epoch: self.epoch,
            after: self.next,
        }
    }
}

/// One `(device_id, verifying key)` pair the node knows and trusts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: [u8; 32],
    /// 33-byte compressed SEC1 key.
    pub public_key_sec1: Vec<u8>,
}

/// `/devices` response: every device this node will vouch for, so a puller can
/// verify transitively-relayed ops from devices it never met directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevicesResp {
    pub devices: Vec<DeviceEntry>,
}

pub fn encode_order_key(key: &OrderKey) -> String {
    crate::identity::encode_hex(&key.to_wire())
}

pub(crate) fn decode_fixed_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    decode_hex(encoded)?.try_into().ok()
}
