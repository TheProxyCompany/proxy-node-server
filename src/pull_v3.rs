//! Mesh pull protocol v3 — wire types and cryptographic envelope primitives.
//!
//! v3 serves two channels per drain over the same authenticated surface:
//!
//! - **Channel B (backbone, positional)** — the peer's arrival stream on the
//!   same durable relay cursor, epoch, reset, and floor semantics as v2,
//!   omitting arrivals whose order key is strictly above the puller's claim for
//!   that op's origin (which are guaranteed delivery on channel A).
//! - **Channel A (overlay, keyed)** — a per-origin ascending diff strictly
//!   above the puller's claims.
//!
//! Every missing op lands on at least one channel: if its arrival sequence is
//! above the channel-B cursor, it is served on channel B when its key is at or
//! below the puller's claim for its origin, and on channel A when its key is
//! strictly above that claim.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[cfg(feature = "daemon")]
use crate::error::{IdentityError, OpError};
#[cfg(feature = "daemon")]
use crate::hlc::Hlc;
use crate::identity::DeviceId;
#[cfg(feature = "daemon")]
use crate::identity::DeviceIdentity;
use crate::op::OrderKey;
#[cfg(feature = "daemon")]
use crate::op::{ENVELOPE_VERSION, OpBody, SignedOp, StoreId};

#[cfg(feature = "pull-http")]
pub use crate::net::{
    DISCOVERY_RESCAN_INTERVAL, MESH_AUDIT_ENV, MESH_PEERS_ENV, MeshPullHost, MeshPullSocket,
    NEWEST_FIRST_PREVIEW_GAP, OpLogPullSocket, PULL_FALLBACK_INTERVAL, PullAdmission, PullStorage,
    PullV3Handler, REGISTER_RETRY_BACKOFF, TRELLIS_SWEEP_INTERVAL, V3_NO_PROGRESS_LIMIT, V3Outcome,
    V3Progress, WATCH_REPROBE_INTERVAL, admit_pull_ack_v3, apply_pull_page_v3,
    authenticate_pull_request_v3, build_keyed_channel_v3, build_pull_page_v3,
    classify_pull_request_error, decode_epoch, decode_order_key, decode_page_op, drain_v3_pages,
    encode_origin_rows, endpoint_has_confidential_transport, inflated_claims, is_cgnat_ip,
    is_loopback_host, keyed_resume, parse_mesh_peers, parse_mesh_peers_from, persist_v3_reset,
    preview_head_window_v3, preview_resume_after, reset_pull_page_v3, sweep_store_v3, unix_ms,
    v3_http_client, v3_needs_reset, v3_progress, v3_pull_router, validate_v3_reset,
};

/// Wire version spoken on [`PULL_PATH`].
pub const PULL_V3_VERSION: u8 = 1;

/// Route the v3 pull request posts to. Absence (404/405) is the mixed-fleet
/// feature-detect: the link falls back to the v2 loop.
pub const PULL_PATH: &str = "/mesh/v3/pull";

/// Signed-envelope store id for a v3 pull request.
pub const PULL_REQUEST_STORE_ID: &str = "mesh-pull-request";

/// Signed-envelope store id for a v3 pull response page.
pub const PULL_PAGE_STORE_ID: &str = "mesh-pull-page";

/// Alias for [`PULL_PAGE_STORE_ID`].
pub const PULL_RESPONSE_STORE_ID: &str = PULL_PAGE_STORE_ID;

/// Hard cap on entries a single page may carry, per channel.
pub const PAGE_LIMIT_MAX: usize = 8192;

/// Largest number of envelopes one v3 page carries across both channels.
pub const V3_PAGE_LIMIT_MAX: u32 = PAGE_LIMIT_MAX as u32;

/// Byte governor for one v3 page before cutting with a resume token.
pub const V3_PAGE_BYTE_BUDGET: usize = 32 * 1024 * 1024;

/// Body cap for a v3 pull request.
pub const MAX_V3_REQUEST_BYTES: usize = 256 * 1024;

/// Body cap for a v3 pull response page.
pub const MAX_V3_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Accepted clock skew on a signed pull request, matching the v2 tier.
pub const MAX_REQUEST_SKEW_MS: i64 = 120_000;

/// Which channel a paged drain resumes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullPhase {
    /// Channel B, the positional arrival stream.
    Backfill,
    /// Channel A, the per-origin keyed diff.
    Keyed,
}

/// Where the next page picks up. The server echoes it; the client returns it
/// verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeV3 {
    pub phase: PullPhase,
    /// Channel B position — meaningful in [`PullPhase::Backfill`].
    pub after_seq: u64,
    /// Channel A origin: lowercase hex device id — meaningful in
    /// [`PullPhase::Keyed`].
    pub origin: String,
    /// Channel A position within that origin: 72-byte [`OrderKey`] wire hex.
    pub after_key: String,
}

/// One origin device's high-water mark in a puller's coverage vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OriginHeadV3 {
    pub origin: DeviceId,
    pub head: OrderKey,
}

impl OriginHeadV3 {
    pub fn new(origin: DeviceId, head: OrderKey) -> Self {
        Self { origin, head }
    }

    pub fn to_wire_pair(&self) -> (String, String) {
        (
            self.origin.to_hex(),
            crate::identity::encode_hex(&self.head.to_wire()),
        )
    }

    pub fn from_wire_pair(origin_hex: &str, head_hex: &str) -> Option<Self> {
        let origin = DeviceId::from_hex(origin_hex).ok()?;
        let wire: [u8; 72] = crate::identity::decode_hex(head_hex)?.try_into().ok()?;
        let head = OrderKey::from_wire(&wire);
        (head.device == origin).then_some(Self { origin, head })
    }
}

/// Per-origin high-water claims (`origin_device -> highest_covered_order_key`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageVector(pub BTreeMap<DeviceId, OrderKey>);

impl CoverageVector {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Whether `key` is at or below this device's claim for `key`'s origin.
    /// Ops that answer `true` are served positionally on Channel B, not on Channel A.
    pub fn covers(&self, key: &OrderKey) -> bool {
        self.0.get(&key.device).is_some_and(|claim| *key <= *claim)
    }

    /// Encode this coverage vector into the wire map carried by [`PullRequestV3::coverage`].
    pub fn to_wire_map(&self) -> BTreeMap<String, String> {
        self.0
            .iter()
            .map(|(origin, head)| OriginHeadV3::new(*origin, *head).to_wire_pair())
            .collect()
    }

    /// Decode a wire map (`origin_hex -> order_key_wire_hex`) into a [`CoverageVector`].
    pub fn from_wire_map(wire: &BTreeMap<String, String>) -> Self {
        Self(
            wire.iter()
                .filter_map(|(origin, key)| OriginHeadV3::from_wire_pair(origin, key))
                .map(|entry| (entry.origin, entry.head))
                .collect(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestV3 {
    /// Protocol revision. Currently [`PULL_V3_VERSION`].
    pub version: u8,
    /// The puller's claims: origin device hex -> [`OrderKey`] wire hex. An
    /// origin absent from the map claims nothing.
    pub coverage: BTreeMap<String, String>,
    /// The puller's durable v2 cursor epoch, 32-byte hex. All zeros means none.
    pub relay_epoch: String,
    /// The puller's durable v2 cursor sequence. Recorded server-side as this
    /// peer's compaction acknowledgment when the epoch matches.
    pub relay_after: u64,
    pub resume: Option<ResumeV3>,
    pub limit: u32,
    /// Diagnostic: channel A ignores claims and re-serves each origin in full.
    pub audit: bool,
    /// Restrict the page to one store's ops, served on the keyed channel only.
    #[serde(default)]
    pub store: Option<String>,
    pub issued_at_ms: i64,
}

impl PullRequestV3 {
    /// Decode well-formed `(origin, OrderKey)` claims, skipping malformed or
    /// mismatched entries.
    pub fn decode_coverage(&self) -> BTreeMap<DeviceId, OrderKey> {
        CoverageVector::from_wire_map(&self.coverage).0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullPageV3 {
    pub version: u8,
    /// The server's current stream epoch, 32-byte hex.
    pub epoch: String,
    /// v2 reset semantics for channel B: the puller adopts `epoch` and
    /// restarts at `floor`.
    pub reset: bool,
    /// The server's `compacted_through_seq`.
    pub floor: u64,
    /// Channel B: `(relay_seq, base64 SignedOp envelope)` in arrival order,
    /// carrying only entries whose key is at or below the puller's claim.
    pub backfill: Vec<(u64, String)>,
    /// Channel A: base64 envelopes, ascending within an origin, origins
    /// non-decreasing by raw device-id bytes.
    pub keyed: Vec<String>,
    /// The last arrival sequence scanned on channel B. Advances even when
    /// every scanned entry was filtered out, so a fully-covered stream drains
    /// without re-walking.
    pub next_relay_seq: u64,
    /// The server's current arrival head.
    #[serde(default)]
    pub head_seq: u64,
    /// `None` exactly when `complete`.
    pub resume: Option<ResumeV3>,
    pub complete: bool,
    pub snapshot_recommended: bool,
    /// Echo of the request's `store` filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
}

/// Seal a [`PullRequestV3`] into a canonical [`SignedOp`] wire envelope under
/// [`PULL_REQUEST_STORE_ID`].
#[cfg(feature = "daemon")]
pub fn sign_pull_request_v3(
    request: &PullRequestV3,
    identity: &DeviceIdentity,
    hlc: Hlc,
) -> Result<Vec<u8>, String> {
    let payload =
        serde_json::to_vec(request).map_err(|error| format!("encode pull v3 request: {error}"))?;
    let store = StoreId::new(PULL_REQUEST_STORE_ID).map_err(|error| error.to_string())?;
    let op = SignedOp::seal(
        OpBody {
            v: ENVELOPE_VERSION,
            hlc,
            device: identity.device_id(),
            store,
            payload,
        },
        identity,
    )
    .map_err(|error| format!("sign pull v3 request: {error}"))?;
    op.to_bytes()
        .map_err(|error| format!("encode pull v3 request envelope: {error}"))
}

/// Verify a signed [`PullRequestV3`] envelope against the requester's stored
/// SEC1 public key and clock-skew bound.
#[cfg(feature = "daemon")]
pub fn verify_pull_request_v3<F>(
    bytes: &[u8],
    now_ms: i64,
    lookup_sec1: F,
) -> Result<(DeviceId, PullRequestV3), String>
where
    F: FnOnce(&DeviceId) -> Result<Option<[u8; 33]>, String>,
{
    let op = SignedOp::from_bytes(bytes)
        .map_err(|error| format!("Invalid signed pull envelope: {error}"))?;
    if op.body.store.as_str() != PULL_REQUEST_STORE_ID {
        return Err("Invalid pull signature domain".to_string());
    }
    let peer = op.body.device;
    let stored_key =
        lookup_sec1(&peer)?.ok_or_else(|| "Pull requester has no stored mesh key".to_string())?;
    op.verify_with_sec1(&stored_key)
        .map_err(|error| match error {
            OpError::Identity(
                IdentityError::InvalidPublicKey | IdentityError::InvalidLength { .. },
            ) => {
                format!("Invalid stored mesh key: {error}")
            }
            OpError::DeviceMismatch => "Stored mesh key does not derive the signer".to_string(),
            other => format!("Invalid pull signature: {other}"),
        })?;
    let request: PullRequestV3 = serde_json::from_slice(&op.body.payload)
        .map_err(|error| format!("Invalid payload: {error}"))?;
    if request.version != PULL_V3_VERSION {
        return Err("Unsupported pull protocol version".to_string());
    }
    let skew = i128::from(now_ms) - i128::from(request.issued_at_ms);
    if skew.unsigned_abs() > MAX_REQUEST_SKEW_MS as u128 {
        return Err("Pull request expired".to_string());
    }
    Ok((peer, request))
}

/// Seal a [`PullPageV3`] into a canonical [`SignedOp`] wire envelope under
/// [`PULL_PAGE_STORE_ID`].
#[cfg(feature = "daemon")]
pub fn seal_pull_page_v3(
    page: &PullPageV3,
    identity: &DeviceIdentity,
    hlc: Hlc,
) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(page).map_err(|error| format!("encode pull page: {error}"))?;
    let store = StoreId::new(PULL_PAGE_STORE_ID).map_err(|error| error.to_string())?;
    let op = SignedOp::seal(
        OpBody {
            v: ENVELOPE_VERSION,
            hlc,
            device: identity.device_id(),
            store,
            payload,
        },
        identity,
    )
    .map_err(|error| format!("sign pull page: {error}"))?;
    op.to_bytes()
        .map_err(|error| format!("encode pull page envelope: {error}"))
}

/// Verify that a signed [`PullPageV3`] envelope came from `peer` under its
/// pinned compressed SEC1 key and respects protocol version and entry caps.
#[cfg(feature = "daemon")]
pub fn verify_pull_page_v3(
    bytes: &[u8],
    peer: &DeviceId,
    peer_key: &[u8; 33],
) -> Result<PullPageV3, String> {
    let op = SignedOp::from_bytes(bytes)
        .map_err(|error| format!("invalid v3 pull page envelope: {error}"))?;
    if op.body.store.as_str() != PULL_PAGE_STORE_ID {
        return Err("v3 pull page used an invalid signature domain".to_string());
    }
    if op.body.device != *peer {
        return Err("v3 pull page was signed by another device".to_string());
    }
    op.verify_with_sec1(peer_key).map_err(|error| match error {
        OpError::Identity(
            IdentityError::InvalidPublicKey | IdentityError::InvalidLength { .. },
        ) => {
            format!("invalid pinned peer key: {error}")
        }
        OpError::DeviceMismatch => "pinned peer key does not derive the peer".to_string(),
        other => format!("invalid v3 pull page signature: {other}"),
    })?;
    let page: PullPageV3 = serde_json::from_slice(&op.body.payload)
        .map_err(|error| format!("decode v3 pull page: {error}"))?;
    if page.version != PULL_V3_VERSION {
        return Err("unsupported v3 pull page version".to_string());
    }
    if page.backfill.len() > PAGE_LIMIT_MAX || page.keyed.len() > PAGE_LIMIT_MAX {
        return Err("oversized v3 pull page".to_string());
    }
    Ok(page)
}

#[cfg(all(test, feature = "daemon"))]
mod tests {
    use super::*;
    use crate::op::OpId;

    #[test]
    fn request_and_page_envelopes_round_trip_and_authenticate_peer() {
        let client = DeviceIdentity::generate();
        let server = DeviceIdentity::generate();
        let head = OrderKey {
            hlc: Hlc(42),
            device: client.device_id(),
            op_id: OpId::from_bytes([0x11; 32]),
        };
        let (origin_hex, head_hex) = OriginHeadV3::new(client.device_id(), head).to_wire_pair();
        let request = PullRequestV3 {
            version: PULL_V3_VERSION,
            coverage: BTreeMap::from([(origin_hex, head_hex)]),
            relay_epoch: "00".repeat(32),
            relay_after: 7,
            resume: None,
            limit: V3_PAGE_LIMIT_MAX,
            audit: false,
            store: Some("trellis".to_string()),
            issued_at_ms: 1_000_000,
        };
        let request_bytes = sign_pull_request_v3(&request, &client, Hlc(10)).unwrap();
        let (verified_peer, verified_request) =
            verify_pull_request_v3(&request_bytes, 1_000_500, |peer| {
                Ok((*peer == client.device_id()).then(|| client.public_key_sec1()))
            })
            .unwrap();
        assert_eq!(verified_peer, client.device_id());
        assert_eq!(verified_request, request);
        assert_eq!(
            verified_request.decode_coverage().get(&client.device_id()),
            Some(&head)
        );

        let expired =
            verify_pull_request_v3(&request_bytes, 1_000_000 + MAX_REQUEST_SKEW_MS + 1, |_| {
                Ok(Some(client.public_key_sec1()))
            });
        assert!(expired.is_err());

        let page = PullPageV3 {
            version: PULL_V3_VERSION,
            epoch: "aa".repeat(32),
            reset: false,
            floor: 0,
            backfill: vec![(1, "Zm9v".to_string())],
            keyed: vec!["YmFy".to_string()],
            next_relay_seq: 1,
            head_seq: 5,
            resume: Some(ResumeV3 {
                phase: PullPhase::Keyed,
                after_seq: 0,
                origin: client.device_id().to_hex(),
                after_key: crate::identity::encode_hex(&head.to_wire()),
            }),
            complete: false,
            snapshot_recommended: false,
            store: Some("trellis".to_string()),
        };
        let page_bytes = seal_pull_page_v3(&page, &server, Hlc(20)).unwrap();
        let verified_page =
            verify_pull_page_v3(&page_bytes, &server.device_id(), &server.public_key_sec1())
                .unwrap();
        assert_eq!(verified_page, page);

        let wrong_peer =
            verify_pull_page_v3(&page_bytes, &client.device_id(), &client.public_key_sec1());
        assert!(wrong_peer.is_err());

        let mismatched_key =
            verify_pull_page_v3(&page_bytes, &server.device_id(), &client.public_key_sec1());
        assert_eq!(
            mismatched_key.unwrap_err(),
            "pinned peer key does not derive the peer"
        );

        let mismatched_request_key = verify_pull_request_v3(&request_bytes, 1_000_500, |_| {
            Ok(Some(server.public_key_sec1()))
        });
        assert_eq!(
            mismatched_request_key.unwrap_err(),
            "Stored mesh key does not derive the signer"
        );

        let cross_domain = verify_pull_page_v3(
            &request_bytes,
            &client.device_id(),
            &client.public_key_sec1(),
        );
        assert_eq!(
            cross_domain.unwrap_err(),
            "v3 pull page used an invalid signature domain"
        );
    }
}
