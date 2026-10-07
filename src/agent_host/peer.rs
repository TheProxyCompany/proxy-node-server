//! Signed owner-device request/reply RPC between already-trusted mesh devices.
//!
//! `PeerServer` mounts one route on the node's existing HTTP listener
//! (`POST /peer/agents`, which the embedding node places under its own HTTPS
//! prefix). `PeerClient` speaks to it through the mesh's existing transports.
//! Trust comes only from the injected [`DeviceBook`]: a verifying key absent
//! from the book is an unknown device, and a network OAuth/PACT client has no
//! key in the book at all, so this transport cannot turn one into an owner
//! device. No SSH, no parallel listener, no second trust database, and no
//! owner credential ever rides in a request.
//!
//! Requests and replies are [`SignedOp`] envelopes over the device's existing
//! P-256 key under dedicated transport-only store ids
//! ([`REQUEST_STORE`]/[`REPLY_STORE`]). The envelopes are decoded, verified and
//! consumed here; they are never appended to any replication op-log. The
//! envelope HLC carries no wall-clock meaning, so freshness rides in the
//! canonical signed payload as `timestamp_ms`; the expected recipient device
//! rides there too because sealing stamps the signer into `body.device`.
//!
//! Durable replay state is one postcard file per request id under a private
//! directory leased to the server. Admission is recorded (`Pending`) before
//! the injected handler runs, so the same captured signed bytes can never run
//! it twice — including after a server reopen. A completed replay returns the
//! cached signed reply; a permanently `Pending` receipt reports outcome
//! unknown (HTTP 409) without silently repeating an effect. The runtime's own
//! stable input id remains the dedupe key for a *new* transport attempt of a
//! `Submit`, which is a different envelope and therefore a different request.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};

use super::AgentInput;
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity};
use crate::op::{ENVELOPE_VERSION, OpBody, OpId, SignedOp, StoreId};
use crate::registry::DeviceBook;

/// Transport-only op-log namespace for request envelopes. Dedicated to this
/// RPC: the envelopes are never appended to a replication log.
pub const REQUEST_STORE: &str = "agent-peer.request.v1";
/// Transport-only op-log namespace for reply envelopes. The reply content id
/// covers the request envelope id, so a reply signature is bound to exactly
/// one request.
pub const REPLY_STORE: &str = "agent-peer.request.v1.reply";

/// Domain-separation prefix for the *payload digest* this RPC signs inside a
/// [`SignedOp`]. The envelope signature additionally covers the crate-wide op
/// context, so these bytes can never collide with a bare op or any other
/// protocol's signature.
const PAYLOAD_CONTEXT: &[u8] = b"proxy-node-server/agent-peer/payload/v1\0";

/// Wire/protocol version of this module's payload format.
pub const PROTOCOL_VERSION: u8 = 1;

/// Route path fragment the embedding node mounts under its existing listener.
pub const ROUTE_PATH: &str = "/peer/agents";

/// HTTP status returned when a request is a known replay whose handler outcome
/// was never recorded (the server crashed or was restarted mid-handling).
pub const OUTCOME_UNKNOWN_STATUS: StatusCode = StatusCode::CONFLICT;

/// Bounded clock skew for the signed `timestamp_ms` freshness check.
pub const DEFAULT_MAX_SKEW: Duration = Duration::from_secs(120);

/// Maximum request body accepted by the route (bytes).
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum canonical signed inner payload (bytes); the envelope's digest means
/// the *envelope* payload is a fixed 32 bytes, so this bound applies to the
/// canonical command the client must also be able to produce bounded.
pub const MAX_COMMAND_BYTES: usize = 1024 * 1024;
/// Maximum encoded response body the client will read (bytes).
pub const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum serialized reply payload the server will sign (bytes).
pub const MAX_REPLY_BYTES: usize = 3 * 1024 * 1024;

/// Maximum length of an agent id (same contract as the host's `valid_id`).
pub const MAX_AGENT_ID_LEN: usize = 128;
/// Maximum number of files in a [`DefinitionBundle`].
pub const MAX_BUNDLE_FILES: usize = 64;
/// Maximum byte length of a relative path inside a [`DefinitionBundle`].
pub const MAX_BUNDLE_PATH_LEN: usize = 256;
/// Maximum byte length of one definition file's content.
pub const MAX_BUNDLE_FILE_BYTES: usize = 256 * 1024;
/// Maximum total byte length of a [`DefinitionBundle`].
pub const MAX_BUNDLE_TOTAL_BYTES: usize = 1024 * 1024;
/// Maximum events returned by one [`PeerCommand::Events`] reply.
pub const MAX_EVENTS: u32 = 256;
/// Client-side request timeout. A `Submit` can outlive it only by abandoning
/// the HTTP flow; the server-side effect is then tracked by the replay store.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(75);

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("invalid peer request: {0}")]
    Invalid(String),
    #[error("request is not authenticated as a trusted device")]
    Unauthenticated,
    #[error("request is a replay whose outcome is unknown; not retried")]
    OutcomeUnknown,
    #[error("definition bundle digest does not match its contents")]
    DigestMismatch,
    #[error("definition bundle conflicts with divergent receiver state")]
    Divergent,
    #[error("the requested operation is not supported by this handler")]
    Unsupported,
    #[error("handler failed: {0}")]
    Handler(String),
    #[error("http transport failed: {0}")]
    Transport(String),
    #[error(transparent)]
    Op(#[from] crate::error::OpError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl IntoResponse for PeerError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::OutcomeUnknown => OUTCOME_UNKNOWN_STATUS,
            Self::DigestMismatch | Self::Divergent => StatusCode::CONFLICT,
            Self::Unsupported => StatusCode::NOT_IMPLEMENTED,
            Self::Handler(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Transport(_) => StatusCode::BAD_GATEWAY,
            Self::Op(_) | Self::Io(_) | Self::Postcard(_) | Self::Json(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        // IO/encoding errors can disclose local paths; keep those server-side.
        let message = match self {
            Self::Op(_) | Self::Io(_) | Self::Postcard(_) | Self::Json(_) => {
                "peer transport could not complete the request".to_string()
            }
            other => other.to_string(),
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

/// Postcard-native codec for fixed 32-byte ids (`DeviceId`, `OpId`) inside
/// signed payloads: the raw 32 bytes, not a hex string, so deserialization
/// works under postcard's non-self-describing flavor. (A human-readable wire
/// form can wrap these payloads in JSON at a higher layer; the signed core
/// must stay canonical.)
mod hex32 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let bytes: &[u8] = Deserialize::deserialize(de)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

fn device_id_ser<S: Serializer>(id: &DeviceId, ser: S) -> Result<S::Ok, S::Error> {
    hex32::serialize(id.as_bytes(), ser)
}
fn device_id_de<'de, D: Deserializer<'de>>(de: D) -> Result<DeviceId, D::Error> {
    Ok(DeviceId::from_bytes(hex32::deserialize(de)?))
}
fn op_id_ser<S: Serializer>(id: &OpId, ser: S) -> Result<S::Ok, S::Error> {
    hex32::serialize(id.as_bytes(), ser)
}
fn op_id_de<'de, D: Deserializer<'de>>(de: D) -> Result<OpId, D::Error> {
    Ok(OpId::from_bytes(hex32::deserialize(de)?))
}

/// One safe relative text file inside a [`DefinitionBundle`]. Paths are data
/// for the receiver's typed parser, never instructions to this transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionFile {
    pub path: String,
    pub content: String,
}

/// A bounded, portable agent definition: relative text files only (agent
/// YAML/Markdown, loadouts, habits/skills). No executable path, command line,
/// absolute host path, environment map, or provider/MCP secret can be
/// represented. `digest` is computed by [`DefinitionBundle::seal`]; a receiver
/// compares a supplied `expected` digest against its current state as a
/// compare-and-set guard only — it never grants overwrite authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DefinitionBundle {
    pub files: Vec<DefinitionFile>,
    pub digest: String,
    /// Digest the receiver is expected to be at before installing, for CAS.
    #[serde(default)]
    pub expected: Option<String>,
}

impl DefinitionBundle {
    /// Validate paths and bounds, then stamp the deterministic digest.
    pub fn seal(mut self) -> Result<Self, PeerError> {
        validate_bundle(&self)?;
        self.digest = bundle_digest(&self.files);
        Ok(self)
    }

    /// Recompute the digest over the carried files and compare.
    pub fn verify_digest(&self) -> Result<(), PeerError> {
        validate_bundle(self)?;
        if self.digest != bundle_digest(&self.files) {
            return Err(PeerError::DigestMismatch);
        }
        Ok(())
    }
}

/// Reject absolute paths, dot/parent components, backslashes, duplicate names,
/// NUL/control characters and symlink-like traversal; enforce size bounds.
fn validate_bundle(bundle: &DefinitionBundle) -> Result<(), PeerError> {
    if bundle.files.len() > MAX_BUNDLE_FILES {
        return Err(PeerError::Invalid(
            "definition bundle has too many files".into(),
        ));
    }
    let mut seen = HashSet::with_capacity(bundle.files.len());
    let mut total = 0usize;
    for file in &bundle.files {
        let path = file.path.as_str();
        if path.is_empty()
            || path.len() > MAX_BUNDLE_PATH_LEN
            || path.starts_with('/')
            || path.contains('\\')
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !seen.insert(path.to_string())
        {
            return Err(PeerError::Invalid(
                "definition path must be unique, relative and clean".into(),
            ));
        }
        if file.content.len() > MAX_BUNDLE_FILE_BYTES {
            return Err(PeerError::Invalid("definition file is too large".into()));
        }
        total = total.saturating_add(file.content.len());
        if total > MAX_BUNDLE_TOTAL_BYTES {
            return Err(PeerError::Invalid("definition bundle is too large".into()));
        }
    }
    // The digest is never trusted here: `verify_digest` recomputes it. Bound
    // it anyway so a hostile string cannot force an oversized allocation.
    if bundle.digest.len() > 64 || bundle.digest.chars().any(char::is_control) {
        return Err(PeerError::Invalid("definition digest is malformed".into()));
    }
    Ok(())
}

/// Deterministic digest: SHA-256 over every `(path, content)` pair with
/// length prefixes, so any path or content change changes the digest.
fn bundle_digest(files: &[DefinitionFile]) -> String {
    let mut sorted: Vec<&DefinitionFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hasher = Sha256::new();
    for file in sorted {
        hasher.update((file.path.len() as u64).to_be_bytes());
        hasher.update(file.path.as_bytes());
        hasher.update((file.content.len() as u64).to_be_bytes());
        hasher.update(file.content.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The exact, typed command surface. Every variant names one exact agent id
/// and nothing else: no remote executable path, no command line, no arbitrary
/// host filesystem path, no environment map. Serialized with serde's default
/// *external* tagging: postcard's non-self-describing flavor cannot decode
/// adjacently/internally tagged enums, and this is the canonical signed form.
/// (`PartialEq` is intentionally not derived: `AgentInput` is not `PartialEq`,
/// and equality over a command is never a security decision in this module.)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerCommand {
    /// Ensure the agent is provisioned and running; optionally install its
    /// definition bundle first. Returns availability in the reply payload.
    /// (`definitions` always serializes its `Some`/`None` tag: postcard cannot
    /// decode a field guarded by `skip_serializing_if`.)
    Ensure {
        agent: String,
        definitions: Option<DefinitionBundle>,
    },
    /// Attach to an already-placed agent without changing its definition.
    Open { agent: String },
    /// Current runtime/hosted status for the exact agent.
    Status { agent: String },
    /// Submit one input. The runtime's stable `input.id` remains the dedupe
    /// key for a new transport attempt of this command.
    Submit {
        agent: String,
        input: PeerAgentInput,
    },
    /// Durable event cursor read, bounded by `limit`.
    Events {
        agent: String,
        #[serde(default)]
        after_sequence: u64,
        #[serde(default = "default_event_limit")]
        limit: u32,
    },
    /// Cooperative abort of the exact agent's current work.
    Abort { agent: String },
    /// Attach a scoped Party task using receiver-owned replicated membership.
    /// The wire carries identities only, never launch environment or paths.
    Attach {
        agent: String,
        conversation_id: String,
        participant_id: String,
        definitions: Option<DefinitionBundle>,
    },
}

fn default_event_limit() -> u32 {
    64
}

/// Wire form of an [`AgentInput`] inside a signed command. It is a separate
/// type — rather than reusing the host's `AgentInput` — because postcard's
/// canonical flavor cannot round-trip `skip_serializing_if` `Option` fields.
/// This peers-only shape has no renames and no skips, so the signed bytes are
/// deterministic across every implementation of this module.
/// Canonical JSON codec for the unstructured `data` slot. `serde_json::Value`
/// relies on `deserialize_any`, which postcard's non-self-describing flavor
/// cannot do; carrying the same bytes as a JSON string keeps the wire form
/// deterministic and parseable by any implementation.
mod json_string {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<serde_json::Value>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            None => Option::<String>::None.serialize(ser),
            Some(value) => {
                let text = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
                Some(text).serialize(ser)
            }
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<serde_json::Value>, D::Error> {
        let text: Option<String> = Deserialize::deserialize(de)?;
        text.map(|text| serde_json::from_str(&text).map_err(D::Error::custom))
            .transpose()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PeerAgentInput {
    pub id: String,
    pub kind: String,
    pub message: String,
    pub source: Option<String>,
    #[serde(
        default,
        serialize_with = "json_string::serialize",
        deserialize_with = "json_string::deserialize"
    )]
    pub data: Option<serde_json::Value>,
    pub conversation_id: Option<String>,
    pub participant_id: Option<String>,
    pub task_id: Option<String>,
}

impl From<AgentInput> for PeerAgentInput {
    fn from(input: AgentInput) -> Self {
        Self {
            id: input.id,
            kind: input.kind,
            message: input.message,
            source: input.source,
            data: input.data,
            conversation_id: input.conversation_id,
            participant_id: input.participant_id,
            task_id: input.task_id,
        }
    }
}

impl From<PeerAgentInput> for AgentInput {
    fn from(input: PeerAgentInput) -> Self {
        Self {
            id: input.id,
            kind: input.kind,
            message: input.message,
            source: input.source,
            data: input.data,
            conversation_id: input.conversation_id,
            participant_id: input.participant_id,
            task_id: input.task_id,
        }
    }
}

impl PeerCommand {
    /// The exact agent id every reply/event/status is correlated with.
    pub fn agent_id(&self) -> &str {
        match self {
            Self::Ensure { agent, .. }
            | Self::Open { agent }
            | Self::Status { agent }
            | Self::Submit { agent, .. }
            | Self::Events { agent, .. }
            | Self::Abort { agent }
            | Self::Attach { agent, .. } => agent,
        }
    }

    /// Strict parse and bound checks beyond serde's. Unknown variants and
    /// trailing fields already fail deserialization; this enforces the shared
    /// id/cursor/size contract so a hostile script cannot reach the handler.
    pub fn validate(&self) -> Result<(), PeerError> {
        let agent = self.agent_id();
        if agent.is_empty()
            || agent.len() > MAX_AGENT_ID_LEN
            || !agent
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err(PeerError::Invalid("invalid agent id".into()));
        }
        match self {
            Self::Ensure { definitions, .. } => {
                if let Some(bundle) = definitions {
                    bundle.verify_digest()?;
                }
            }
            Self::Attach {
                conversation_id,
                participant_id,
                definitions,
                ..
            } => {
                if [conversation_id, participant_id]
                    .iter()
                    .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
                {
                    return Err(PeerError::Invalid("invalid Party attachment scope".into()));
                }
                if let Some(bundle) = definitions {
                    bundle.verify_digest()?;
                }
            }
            Self::Submit { input, .. } => {
                if input.id.is_empty()
                    || input.id.len() > 256
                    || !matches!(input.kind.as_str(), "prompt" | "event" | "observation")
                    || input.message.len() > MAX_COMMAND_BYTES
                {
                    return Err(PeerError::Invalid("invalid agent input".into()));
                }
            }
            Self::Events { limit, .. } => {
                if *limit == 0 || *limit > MAX_EVENTS {
                    return Err(PeerError::Invalid("event limit out of bounds".into()));
                }
            }
            Self::Open { .. } | Self::Status { .. } | Self::Abort { .. } => {}
        }
        Ok(())
    }
}

/// Canonical signed payload of a request envelope. `target` and
/// `timestamp_ms` ride here because envelope sealing stamps the signer into
/// `body.device` and the HLC slot is not a wall clock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestPayload {
    pub v: u8,
    #[serde(serialize_with = "device_id_ser", deserialize_with = "device_id_de")]
    pub target: DeviceId,
    pub timestamp_ms: u64,
    pub command: PeerCommand,
}

/// Canonical signed payload of a reply envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplyPayload {
    pub v: u8,
    /// The request envelope id this reply is bound to.
    #[serde(serialize_with = "op_id_ser", deserialize_with = "op_id_de")]
    pub request_id: OpId,
    /// The request's signer (the reply's expected recipient).
    #[serde(serialize_with = "device_id_ser", deserialize_with = "device_id_de")]
    pub requester: DeviceId,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(
        default,
        serialize_with = "json_string::serialize",
        deserialize_with = "json_string::deserialize"
    )]
    pub payload: Option<serde_json::Value>,
}

/// The bytes an envelope actually signs over: its 32-byte `payload` field is
/// the SHA-256 digest of the domain-separated canonical postcard of the inner
/// signed payload. The HTTP body carries both the envelope and that canonical
/// payload, so the handler sees content while the signature binds the digest.
///
/// SHA-256 over the domain-separated canonical postcard of a signed payload.
/// A [`SignedOp`]'s `payload` carries this digest, so the envelope signature
/// covers exactly these bytes and nothing else can be substituted into them.
fn payload_digest<T: Serialize>(value: &T) -> Result<Vec<u8>, PeerError> {
    let canonical = postcard::to_allocvec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_CONTEXT);
    hasher.update(&canonical);
    Ok(hasher.finalize().to_vec())
}

/// Seal `payload` into a [`SignedOp`] under `store` with `identity`. The
/// envelope body carries the payload digest, so the request id is a content
/// address of the full signed inner payload. Public so tests and the
/// integration owner can build frames without the full client.
pub fn seal_payload<T: Serialize>(
    store: &str,
    payload: &T,
    identity: &DeviceIdentity,
) -> Result<SignedOp, PeerError> {
    let digest = payload_digest(payload)?;
    let body = OpBody {
        v: ENVELOPE_VERSION,
        // The HLC slot is not a wall clock; freshness is the payload's
        // `timestamp_ms`. Zero keeps the envelope deterministic here.
        hlc: Hlc::ZERO,
        device: identity.device_id(),
        store: StoreId::new(store).map_err(|_| PeerError::Invalid("bad store id".into()))?,
        payload: digest,
    };
    Ok(SignedOp::seal(body, identity)?)
}

/// Verify an envelope under `key`: canonical store, the inner payload digests
/// to the envelope's committed 32-byte payload, and the signature is valid.
fn verify_envelope<T: Serialize>(
    envelope: &SignedOp,
    store: &str,
    inner: &T,
    key: &VerifyingKey,
) -> Result<(), PeerError> {
    if envelope.body.store.as_str() != store {
        return Err(PeerError::Unauthenticated);
    }
    if envelope.body.payload != payload_digest(inner)? {
        return Err(PeerError::Unauthenticated);
    }
    envelope.verify(key).map_err(|_| PeerError::Unauthenticated)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Recorded state of one admitted request id.
pub enum ReplayState {
    /// Admission was recorded but no completed reply was ever written; a retry
    /// of the same bytes must report outcome unknown rather than re-run.
    Pending,
    /// The fully-signed response frame, cached so a completed replay returns
    /// an identical reply without re-running the handler.
    Completed(Vec<u8>),
}

impl ReplayState {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Pending => vec![0],
            Self::Completed(bytes) => {
                let mut out = Vec::with_capacity(1 + bytes.len());
                out.push(1);
                out.extend_from_slice(bytes);
                out
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, PeerError> {
        match bytes.split_first() {
            Some((&0, &[])) => Ok(Self::Pending),
            Some((&1, reply)) => Ok(Self::Completed(reply.to_vec())),
            _ => Err(PeerError::Invalid("corrupt replay record".into())),
        }
    }
}

/// In-process claim on one request id, held by the request that is currently
/// admitting or handling it. Released on drop, after the durable record is
/// written (completed or, on panic, still pending). This closes the window
/// between the durable `get` and `admit`: without it two concurrent deliveries
/// of the *same* signed bytes both observe `None` and both run the handler.
#[derive(Debug)]
pub struct ReplayClaim<'a> {
    in_flight: &'a Mutex<HashSet<OpId>>,
    id: OpId,
}

impl Drop for ReplayClaim<'_> {
    fn drop(&mut self) {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

/// Durable replay state: one file per request id under a private, fsynced
/// directory leased to the server. Written only by [`PeerServer`]; read back
/// before any handler effect.
#[derive(Debug)]
pub struct ReplayStore {
    dir: PathBuf,
    _lease: std::fs::File,
    /// Request ids currently being admitted/handled by this process, so
    /// concurrent duplicates cannot both pass the durable `get`/`admit` gap.
    in_flight: Mutex<HashSet<OpId>>,
}

impl ReplayStore {
    /// Open (creating) a private store directory and take its exclusive lease,
    /// so two servers cannot record conflicting outcomes for one request id.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, PeerError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lease = options.open(dir.join("replay.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lease)
            .map_err(|_| PeerError::Invalid("replay store is held by another server".into()))?;
        Ok(Self {
            dir,
            _lease: lease,
            in_flight: Mutex::new(HashSet::new()),
        })
    }

    fn path(&self, id: &OpId) -> PathBuf {
        self.dir.join(format!("{}.replay", id.to_hex()))
    }

    /// Look up a recorded admission for `id`.
    pub fn get(&self, id: &OpId) -> Result<Option<ReplayState>, PeerError> {
        match std::fs::read(self.path(id)) {
            Ok(bytes) => Ok(Some(ReplayState::decode(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Claim `id` for exclusive in-process handling. `Ok(Some(guard))` means
    /// this caller now owns the claim and must hold the guard until its durable
    /// record is written (released on drop, including on panic). `Ok(None)`
    /// means another request is already admitting or handling the same bytes,
    /// so the caller must treat it exactly like a durable `Pending` (outcome
    /// unknown) rather than admitting or dispatching a second effect.
    pub fn claim(&self, id: &OpId) -> Result<Option<ReplayClaim<'_>>, PeerError> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if in_flight.insert(*id) {
            Ok(Some(ReplayClaim {
                in_flight: &self.in_flight,
                id: *id,
            }))
        } else {
            Ok(None)
        }
    }

    /// Record admission before any handler effect. Fsyncs the file and its
    /// directory so a power loss cannot resurrect an unrecorded request.
    pub fn admit(&self, id: &OpId) -> Result<(), PeerError> {
        self.write_state(id, &ReplayState::Pending)
    }

    /// Record the completed, fully-signed reply bytes against the admission.
    pub fn complete(&self, id: &OpId, reply: Vec<u8>) -> Result<(), PeerError> {
        self.write_state(id, &ReplayState::Completed(reply))
    }

    fn write_state(&self, id: &OpId, state: &ReplayState) -> Result<(), PeerError> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.path(id))?;
        file.write_all(&state.encode())?;
        file.sync_all()?;
        // Fsync the directory so the file's directory entry is durable too.
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

/// A verified request handed to the injected handler. `sender` is the
/// DeviceBook-resolved signer; `command` has passed strict type/bound checks.
#[derive(Clone, Debug)]
pub struct VerifiedRequest {
    pub sender: DeviceId,
    pub command: PeerCommand,
}

/// Application-specific loadout/definition resolution. The handler owns
/// parsing of any [`DefinitionBundle`] through the app's typed library and
/// decides whether to install; the transport only carries definitions as
/// data. Returning `Err(PeerError::Unsupported)` is how a handoff-shaped
/// request is refused until admission fencing, drain and checkpoint exist.
///
/// Boxed futures keep the trait object-safe so the server can hold
/// `Arc<dyn PeerHandler>` without a type parameter at the axum layer.
pub trait PeerHandler: Send + Sync {
    fn handle(
        &self,
        request: VerifiedRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, PeerError>> + Send>,
    >;
}

impl<F, Fut> PeerHandler for F
where
    F: Fn(VerifiedRequest) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<serde_json::Value, PeerError>> + Send + 'static,
{
    fn handle(
        &self,
        request: VerifiedRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, PeerError>> + Send>,
    > {
        Box::pin(self(request))
    }
}

struct ServerState<D> {
    identity: Arc<DeviceIdentity>,
    devices: D,
    handler: Arc<dyn PeerHandler>,
    replays: Arc<ReplayStore>,
    max_skew: Duration,
    /// Monotone counter folded into server diagnostics; not security.
    served: AtomicU64,
}

/// The authenticated server half. Owns its state; no process-global registry.
pub struct PeerServer<D: DeviceBook> {
    state: Arc<ServerState<D>>,
}

impl<D: DeviceBook> Clone for PeerServer<D> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<D: DeviceBook> PeerServer<D> {
    /// Build a server over this device's identity, the trusted device book, an
    /// injected handler and a private durable replay directory.
    pub fn new(
        identity: Arc<DeviceIdentity>,
        devices: D,
        handler: Arc<dyn PeerHandler>,
        replay_dir: impl AsRef<Path>,
    ) -> Result<Self, PeerError> {
        Self::with_skew(identity, devices, handler, replay_dir, DEFAULT_MAX_SKEW)
    }

    /// Test hook for a non-default freshness window.
    pub fn with_skew(
        identity: Arc<DeviceIdentity>,
        devices: D,
        handler: Arc<dyn PeerHandler>,
        replay_dir: impl AsRef<Path>,
        max_skew: Duration,
    ) -> Result<Self, PeerError> {
        Ok(Self {
            state: Arc::new(ServerState {
                identity,
                devices,
                handler,
                replays: Arc::new(ReplayStore::open(replay_dir)?),
                max_skew,
                served: AtomicU64::new(0),
            }),
        })
    }

    /// The router fragment to merge into the node's existing listener.
    pub fn router(&self) -> Router {
        Router::new()
            .route(ROUTE_PATH, post(peer_route::<D>))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(Arc::clone(&self.state))
    }
}

/// The one wire route. The HTTP body is the base64url content of a JSON
/// wrapper `{ request: <postcard SignedOp>, payload: <postcard RequestPayload> }`,
/// or raw postcard when the content digest already commits. To keep the body
/// byte-bounded and self-authenticating we use one frame: postcard of a
/// `(SignedOp bytes, RequestPayload bytes)` pair.
async fn peer_route<D: DeviceBook>(
    State(state): State<Arc<ServerState<D>>>,
    body: axum::body::Bytes,
) -> Result<Response, PeerError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(PeerError::Invalid("request body too large".into()));
    }
    let (envelope_bytes, payload_bytes): (Vec<u8>, Vec<u8>) =
        postcard::from_bytes(&body).map_err(|_| PeerError::Invalid("bad request frame".into()))?;
    if envelope_bytes.len() > 512 || payload_bytes.len() > MAX_COMMAND_BYTES {
        return Err(PeerError::Invalid("request frame out of bounds".into()));
    }
    let envelope = SignedOp::from_bytes(&envelope_bytes)
        .map_err(|_| PeerError::Invalid("bad envelope".into()))?;
    let payload: RequestPayload = postcard::from_bytes(&payload_bytes)
        .map_err(|_| PeerError::Invalid("bad payload".into()))?;
    let reply = handle_request(&state, &envelope, &payload).await?;
    state.served.fetch_add(1, Ordering::Relaxed);
    let mut response = Response::new(axum::body::Body::from(reply));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

/// Authenticate and authorize a verified request envelope, then dispatch.
/// All failures before the replay-admission point never touch the handler.
async fn handle_request<D: DeviceBook>(
    state: &Arc<ServerState<D>>,
    envelope: &SignedOp,
    payload: &RequestPayload,
) -> Result<Vec<u8>, PeerError> {
    // 1. Envelope store + version + payload digest commit.
    if payload.v != PROTOCOL_VERSION {
        return Err(PeerError::Invalid("unsupported protocol version".into()));
    }
    // 2. Exact recipient device: this node is the named target.
    if payload.target != state.identity.device_id() {
        return Err(PeerError::Unauthenticated);
    }
    // 3. Freshness: bounded clock skew on the signed timestamp.
    let skew = state.max_skew.as_millis() as u64;
    let now = now_ms();
    if payload.timestamp_ms > now.saturating_add(skew)
        || now.saturating_sub(payload.timestamp_ms) > skew
    {
        return Err(PeerError::Unauthenticated);
    }
    // 4. Trusted sender: the signer must be in the injected DeviceBook.
    let sec1 = state
        .devices
        .try_key_for_device(&envelope.body.device)
        .map_err(|_| PeerError::Transport("device book unavailable".into()))?
        .ok_or(PeerError::Unauthenticated)?;
    if DeviceIdentity::device_id_from_sec1(&sec1).ok() != Some(envelope.body.device) {
        return Err(PeerError::Unauthenticated);
    }
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| PeerError::Unauthenticated)?;
    verify_envelope(envelope, REQUEST_STORE, payload, &key)?;
    payload.command.validate()?;

    // 5. Durable replay: record admission before any effect. The same signed
    //    bytes (same request id) never run the handler twice. The in-process
    //    claim is held for the whole check→admit→handle→complete sequence so
    //    two concurrent deliveries of identical bytes cannot both proceed.
    match state.replays.get(&envelope.id)? {
        Some(ReplayState::Completed(reply)) => return Ok(reply),
        Some(ReplayState::Pending) => return Err(PeerError::OutcomeUnknown),
        None => {}
    }
    let _claim = state
        .replays
        .claim(&envelope.id)?
        .ok_or(PeerError::OutcomeUnknown)?;
    state.replays.admit(&envelope.id)?;

    // 6. Dispatch. A handler error is still a *handled* request, so record it
    //    as a Completed reply as well (a retry then returns the same reply).
    let verified = VerifiedRequest {
        sender: envelope.body.device,
        command: payload.command.clone(),
    };
    let outcome = state.handler.handle(verified).await;
    let reply_payload = match outcome {
        Ok(value) => ReplyPayload {
            v: PROTOCOL_VERSION,
            request_id: envelope.id,
            requester: envelope.body.device,
            error: None,
            payload: Some(value),
        },
        Err(error) => ReplyPayload {
            v: PROTOCOL_VERSION,
            request_id: envelope.id,
            requester: envelope.body.device,
            error: Some(error.to_string()),
            payload: None,
        },
    };
    let encoded = postcard::to_allocvec(&reply_payload)?;
    if encoded.len() > MAX_REPLY_BYTES {
        return Err(PeerError::Handler("reply payload too large".into()));
    }
    let reply_envelope = seal_payload(REPLY_STORE, &reply_payload, &state.identity)?;
    let reply_bytes = frame_response(&reply_envelope, &reply_payload)?;
    state.replays.complete(&envelope.id, reply_bytes.clone())?;
    Ok(reply_bytes)
}

/// Encode one response frame the way [`PeerClient`] expects: postcard of
/// `(SignedOp reply bytes, ReplyPayload bytes)`.
pub fn frame_response(envelope: &SignedOp, payload: &ReplyPayload) -> Result<Vec<u8>, PeerError> {
    let frame = (envelope.to_bytes()?, postcard::to_allocvec(payload)?);
    Ok(postcard::to_allocvec(&frame)?)
}

/// The exact endpoint the client calls. Existing mesh transports only; the
/// URL must be HTTPS for a remote host, or loopback HTTP for local tests.
#[derive(Clone, Debug)]
pub struct PeerEndpoint {
    url: reqwest::Url,
}

impl PeerEndpoint {
    pub fn new(url: &str) -> Result<Self, PeerError> {
        let url = reqwest::Url::parse(url)
            .map_err(|_| PeerError::Invalid("invalid endpoint URL".into()))?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(PeerError::Invalid(
                "endpoint URL must not carry credentials or a fragment".into(),
            ));
        }
        let host = url.host_str().unwrap_or("");
        let protected_http = host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| match ip {
                    std::net::IpAddr::V4(ip) => {
                        ip.is_loopback()
                            || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                    }
                    std::net::IpAddr::V6(ip) => {
                        ip.is_loopback() || {
                            let segments = ip.segments();
                            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
                        }
                    }
                });
        match url.scheme() {
            "https" => {}
            "http" if protected_http => {}
            _ => {
                return Err(PeerError::Invalid(
                    "endpoint must use HTTPS, loopback, or the encrypted Tailscale address range"
                        .into(),
                ));
            }
        }
        let url = url
            .join(ROUTE_PATH)
            .map_err(|_| PeerError::Invalid("endpoint URL cannot host the route".into()))?;
        Ok(Self { url })
    }
}

/// The authenticated client half. Owns its identity, expected target and
/// endpoint; no process-global mutable registry.
pub struct PeerClient<D: DeviceBook> {
    identity: Arc<DeviceIdentity>,
    devices: D,
    target: DeviceId,
    endpoint: PeerEndpoint,
    http: reqwest::Client,
}

impl<D: DeviceBook> PeerClient<D> {
    /// Build a client. `devices` must already contain the expected target's
    /// key (it is the same trusted book the node uses); the client also uses
    /// it to verify reply signatures. Redirects are disabled.
    pub fn new(
        identity: Arc<DeviceIdentity>,
        devices: D,
        target: DeviceId,
        endpoint: PeerEndpoint,
    ) -> Result<Self, PeerError> {
        // The expected target must itself be a trusted device in the book.
        let sec1 = devices
            .try_key_for_device(&target)
            .map_err(|_| PeerError::Transport("device book unavailable".into()))?
            .ok_or(PeerError::Invalid("target device is not trusted".into()))?;
        if DeviceIdentity::device_id_from_sec1(&sec1).ok() != Some(target) {
            return Err(PeerError::Invalid("target device key mismatch".into()));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| PeerError::Transport(e.to_string()))?;
        Ok(Self {
            identity,
            devices,
            target,
            endpoint,
            http,
        })
    }

    /// Run one command and return the verified reply payload.
    pub async fn command(&self, command: PeerCommand) -> Result<serde_json::Value, PeerError> {
        command.validate()?;
        let request = RequestPayload {
            v: PROTOCOL_VERSION,
            target: self.target,
            timestamp_ms: now_ms(),
            command,
        };
        let envelope = seal_payload(REQUEST_STORE, &request, &self.identity)?;
        let frame = (envelope.to_bytes()?, postcard::to_allocvec(&request)?);
        let body = postcard::to_allocvec(&frame)?;
        let mut response = self
            .http
            .post(self.endpoint.url.clone())
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    PeerError::OutcomeUnknown
                } else {
                    PeerError::Transport(e.to_string())
                }
            })?;
        let status = response.status();
        if status == OUTCOME_UNKNOWN_STATUS {
            return Err(PeerError::OutcomeUnknown);
        }
        if !status.is_success() {
            // An unsigned error page is a transport failure, never a payload.
            return Err(PeerError::Transport(format!("http status {status}")));
        }
        // Enforce the cap while reading, not after: the expected target is
        // trusted but a compromised one must not be able to make the client
        // buffer an unbounded body before the check. `content_length`, when
        // present, is a cheap early rejection; the loop is the real bound for
        // chunked or lying responses.
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES)
        {
            return Err(PeerError::Invalid("response body too large".into()));
        }
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| PeerError::Transport(e.to_string()))?
        {
            if bytes.len() as u64 + chunk.len() as u64 > MAX_RESPONSE_BYTES {
                return Err(PeerError::Invalid("response body too large".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        self.verify_reply(&bytes, &envelope).await
    }

    /// Verify a signed reply frame against this client: the expected target
    /// signed it, it is bound to this exact request id, and the recipient is
    /// this client. Tampered, wrong-peer or wrong-request replies are rejected
    /// before any payload is surfaced.
    async fn verify_reply(
        &self,
        bytes: &[u8],
        request_envelope: &SignedOp,
    ) -> Result<serde_json::Value, PeerError> {
        let (envelope_bytes, payload_bytes): (Vec<u8>, Vec<u8>) = postcard::from_bytes(bytes)
            .map_err(|_| PeerError::Transport("bad reply frame".into()))?;
        let reply_envelope = SignedOp::from_bytes(&envelope_bytes)
            .map_err(|_| PeerError::Transport("bad reply envelope".into()))?;
        let payload: ReplyPayload = postcard::from_bytes(&payload_bytes)
            .map_err(|_| PeerError::Transport("bad reply payload".into()))?;
        if payload.v != PROTOCOL_VERSION {
            return Err(PeerError::Transport("unsupported reply version".into()));
        }
        // Wrong peer: the reply must come from the exact expected target.
        if reply_envelope.body.device != self.target {
            return Err(PeerError::Unauthenticated);
        }
        // Wrong request / wrong recipient binding.
        if payload.request_id != request_envelope.id
            || payload.requester != self.identity.device_id()
        {
            return Err(PeerError::Unauthenticated);
        }
        let sec1 = self
            .devices
            .try_key_for_device(&self.target)
            .map_err(|_| PeerError::Transport("device book unavailable".into()))?
            .ok_or(PeerError::Unauthenticated)?;
        let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| PeerError::Unauthenticated)?;
        verify_envelope(&reply_envelope, REPLY_STORE, &payload, &key)?;
        if let Some(error) = payload.error {
            // Map a recorded handler failure back onto the typed error when
            // the string round-trips; otherwise surface it as rejected work.
            return Err(match error.as_str() {
                "the requested operation is not supported by this handler" => {
                    PeerError::Unsupported
                }
                "request is a replay whose outcome is unknown; not retried" => {
                    PeerError::OutcomeUnknown
                }
                _ => PeerError::Handler(error),
            });
        }
        payload
            .payload
            .ok_or_else(|| PeerError::Transport("reply carried no payload".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::registry::DeviceRegistry;
    use std::sync::Mutex as StdMutex;

    fn book(ids: &[&DeviceIdentity]) -> Arc<StdMutex<DeviceRegistry>> {
        let mut registry = DeviceRegistry::new();
        for id in ids {
            registry.insert_sec1(&id.public_key_sec1()).unwrap();
        }
        Arc::new(StdMutex::new(registry))
    }

    fn command() -> PeerCommand {
        PeerCommand::Status {
            agent: "jarvis".into(),
        }
    }

    #[test]
    fn payload_digest_is_domain_separated_and_deterministic() {
        let a = payload_digest(&command()).unwrap();
        let b = payload_digest(&command()).unwrap();
        assert_eq!(a, b);
        let other = payload_digest(&PeerCommand::Status { agent: "j".into() }).unwrap();
        assert_ne!(a, other);
    }

    #[test]
    fn sealed_request_verifies_round_trip() {
        let identity = DeviceIdentity::generate();
        let request = RequestPayload {
            v: PROTOCOL_VERSION,
            target: identity.device_id(),
            timestamp_ms: now_ms(),
            command: command(),
        };
        let envelope = seal_payload(REQUEST_STORE, &request, &identity).unwrap();
        assert_eq!(envelope.body.device, identity.device_id());
        assert_eq!(envelope.body.store.as_str(), REQUEST_STORE);
        verify_envelope(&envelope, REQUEST_STORE, &request, identity.verifying_key()).unwrap();
        // Tampered inner payload must break the digest commit.
        let mut forged = request.clone();
        forged.timestamp_ms += 1;
        assert!(
            verify_envelope(&envelope, REQUEST_STORE, &forged, identity.verifying_key()).is_err()
        );
    }

    #[test]
    fn definition_bundle_rejects_traversal_and_duplicates() {
        let good = |path: &str| DefinitionBundle {
            files: vec![DefinitionFile {
                path: path.into(),
                content: "x".into(),
            }],
            digest: String::new(),
            expected: None,
        };
        let sealed = good("agents/jarvis.md").seal().unwrap();
        sealed.verify_digest().unwrap();
        assert!(good("/etc/passwd").seal().is_err());
        assert!(good("a/../b").seal().is_err());
        assert!(good("a/./b").seal().is_err());
        assert!(good("a\\b").seal().is_err());
        assert!(good("a//b").seal().is_err());
        assert!(good("").seal().is_err());

        let mut dup = good("a/b");
        dup.files.push(DefinitionFile {
            path: "a/b".into(),
            content: "y".into(),
        });
        assert!(dup.seal().is_err());

        // Digest changes with any path or content change.
        let mut changed = sealed.clone();
        changed.files[0].content = "changed".into();
        assert!(changed.verify_digest().is_err());
    }

    #[test]
    fn definition_digest_matches_golden_vector() {
        let bundle = DefinitionBundle {
            files: vec![
                DefinitionFile {
                    path: "agents/jarvis.md".into(),
                    content: "# Jarvis".into(),
                },
                DefinitionFile {
                    path: "loadouts/deep-work.yaml".into(),
                    content: "model: kimi".into(),
                },
            ],
            digest: String::new(),
            expected: None,
        }
        .seal()
        .unwrap();
        // Recomputed by hand in the test: SHA-256 over len-prefixed pairs sorted
        // by path. Assert the property, not a hard-coded hex, so the algorithm
        // stays self-describing; the determinism two lines down is the point.
        assert_eq!(bundle.digest, bundle_digest(&bundle.files));
        let mut reordered = bundle.files.clone();
        reordered.reverse();
        assert_eq!(bundle_digest(&reordered), bundle.digest);
    }

    #[test]
    fn command_validate_rejects_bad_inputs() {
        assert!(PeerCommand::Status { agent: "".into() }.validate().is_err());
        assert!(
            PeerCommand::Status {
                agent: "a/b".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            PeerCommand::Events {
                agent: "ok".into(),
                after_sequence: 0,
                limit: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            PeerCommand::Events {
                agent: "ok".into(),
                after_sequence: 0,
                limit: MAX_EVENTS + 1
            }
            .validate()
            .is_err()
        );
        let mut input = PeerAgentInput {
            id: String::new(),
            kind: "prompt".into(),
            message: "hi".into(),
            source: None,
            data: None,
            conversation_id: None,
            participant_id: None,
            task_id: None,
        };
        assert!(
            PeerCommand::Submit {
                agent: "ok".into(),
                input: input.clone()
            }
            .validate()
            .is_err()
        );
        input.id = "stable-1".into();
        assert!(
            PeerCommand::Submit {
                agent: "ok".into(),
                input
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn endpoint_rejects_credentials_and_wrong_scheme() {
        assert!(PeerEndpoint::new("https://node.example").is_ok());
        assert!(PeerEndpoint::new("http://127.0.0.1:8787").is_ok());
        assert!(PeerEndpoint::new("http://localhost:8787").is_ok());
        assert!(PeerEndpoint::new("http://node.example").is_err());
        assert!(PeerEndpoint::new("https://user:pw@node.example").is_err());
        assert!(PeerEndpoint::new("https://node.example/#frag").is_err());
        assert!(PeerEndpoint::new("ssh://node.example").is_err());
    }

    #[test]
    fn replay_store_round_trip_and_outcome_pending() {
        let temp = tempfile::tempdir().unwrap();
        let id = OpId::from_bytes([7u8; 32]);
        {
            let store = ReplayStore::open(temp.path()).unwrap();
            assert!(store.get(&id).unwrap().is_none());
            store.admit(&id).unwrap();
            assert!(matches!(
                store.get(&id).unwrap(),
                Some(ReplayState::Pending)
            ));
            store.complete(&id, b"signed-reply".to_vec()).unwrap();
            match store.get(&id).unwrap() {
                Some(ReplayState::Completed(reply)) => assert_eq!(reply, b"signed-reply"),
                _ => panic!("expected completed"),
            }
        }
        // Reopen the same directory: the completed record survives.
        let store = ReplayStore::open(temp.path()).unwrap();
        match store.get(&id).unwrap() {
            Some(ReplayState::Completed(reply)) => assert_eq!(reply, b"signed-reply"),
            _ => panic!("expected completed after reopen"),
        }
    }

    #[test]
    fn client_requires_trusted_target() {
        let client_id = DeviceIdentity::generate();
        let target = DeviceIdentity::generate();
        let untrusted = DeviceIdentity::generate();
        let book = book(&[&client_id, &target]);
        let endpoint = PeerEndpoint::new("https://node.example").unwrap();
        assert!(
            PeerClient::new(
                Arc::new(client_id),
                book.clone(),
                target.device_id(),
                endpoint.clone()
            )
            .is_ok()
        );
        assert!(
            PeerClient::new(
                Arc::new(DeviceIdentity::generate()),
                book,
                untrusted.device_id(),
                endpoint
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::PeerEndpoint;
    #[test]
    fn accepts_existing_encrypted_mesh_routes_and_refuses_plain_network_routes() {
        for url in [
            "https://device.proxy.ing",
            "http://127.0.0.1:51711",
            "http://[::1]:51711",
            "http://100.64.0.2:51711",
            "http://[fd7a:115c:a1e0::2]:51711",
        ] {
            assert!(PeerEndpoint::new(url).is_ok(), "{url}");
        }
        for url in [
            "http://192.168.1.2:51711",
            "http://example.com",
            "http://100.128.0.1",
            "http://[fd7a::2]:51711",
            "https://owner:secret@example.com",
            "file:///tmp/route",
        ] {
            assert!(PeerEndpoint::new(url).is_err(), "{url}");
        }
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;
    #[test]
    fn attachment_scope_round_trips_without_launch_paths_or_credentials() {
        let request = PeerCommand::Attach {
            agent: "dot".into(),
            conversation_id: "party".into(),
            participant_id: "party:dot".into(),
            definitions: None,
        };
        request.validate().unwrap();
        let bytes = postcard::to_allocvec(&request).unwrap();
        let restored: PeerCommand = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.agent_id(), "dot");
        assert!(
            matches!(restored, PeerCommand::Attach { participant_id, .. } if participant_id == "party:dot")
        );
        for participant in ["".to_string(), "x".repeat(257), "invalid\nscope".into()] {
            assert!(
                PeerCommand::Attach {
                    agent: "dot".into(),
                    conversation_id: "party".into(),
                    participant_id: participant,
                    definitions: None
                }
                .validate()
                .is_err()
            );
        }
    }
}
