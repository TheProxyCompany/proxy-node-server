//! Open-source external thread sync interface ([`ThreadSourceAdapter`]),
//! built-in harness provider descriptors, and node-to-node signed thread-control
//! wire envelopes (`/thread-sources/v2/challenge`, `/thread-sources/v2/send`).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::encode_hex;

pub const CODEX_PROVIDER: &str = "codex";
pub const HERMES_PROVIDER: &str = "hermes";
pub const CLAUDE_PROVIDER: &str = "claude_code";
pub const CURSOR_PROVIDER: &str = "cursor";
pub const OPENCLAW_PROVIDER: &str = "openclaw";
pub const OPENCODE_PROVIDER: &str = "opencode";
pub const PI_PROVIDER: &str = "pi";
pub const NCODE_PROVIDER: &str = "ncode";
pub const PROXY_HARNESS_PROVIDER: &str = "proxy-harness";

pub const CHALLENGE_REQUEST_STORE_ID: &str = "thread-control-challenge-request";
pub const CHALLENGE_GRANT_STORE_ID: &str = "thread-control-challenge-grant";
pub const SEND_COMMAND_STORE_ID: &str = "thread-control-send";
pub const SEND_RESULT_STORE_ID: &str = "thread-control-result";
pub const CHALLENGE_PATH: &str = "/thread-sources/v2/challenge";
pub const SEND_PATH: &str = "/thread-sources/v2/send";
pub const CONTROL_VERSION: u8 = 2;
pub const CHALLENGE_TTL: Duration = Duration::from_secs(30);
pub const REQUEST_CLOCK_SKEW: Duration = Duration::from_secs(120);
pub const MAX_PENDING_CHALLENGES: usize = 1024;
pub const MAX_PENDING_CHALLENGES_PER_PEER: usize = 64;
pub const MAX_ACTIVE_SENDS: usize = 32;
pub const MAX_ACTIVE_SENDS_PER_PEER: usize = 4;
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveThreadSourceDescriptor {
    pub provider_id: &'static str,
    pub harness_id: &'static str,
    pub display_name: &'static str,
    pub list: bool,
    pub read: bool,
    pub watch: bool,
    pub send_text: bool,
    pub approvals: bool,
}

pub const LIVE_THREAD_SOURCE_DESCRIPTORS: [LiveThreadSourceDescriptor; 9] = [
    LiveThreadSourceDescriptor {
        provider_id: CLAUDE_PROVIDER,
        harness_id: "claude-code",
        display_name: "Claude Code",
        list: true,
        read: true,
        watch: true,
        send_text: true,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: CODEX_PROVIDER,
        harness_id: "codex",
        display_name: "Codex",
        list: true,
        read: true,
        watch: true,
        send_text: false,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: CURSOR_PROVIDER,
        harness_id: "cursor",
        display_name: "Cursor",
        list: true,
        read: true,
        watch: true,
        send_text: false,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: HERMES_PROVIDER,
        harness_id: "hermes-agent",
        display_name: "Hermes",
        list: true,
        read: true,
        watch: true,
        send_text: true,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: OPENCLAW_PROVIDER,
        harness_id: "openclaw",
        display_name: "OpenClaw",
        list: true,
        read: true,
        watch: true,
        send_text: true,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: OPENCODE_PROVIDER,
        harness_id: "opencode",
        display_name: "OpenCode",
        list: true,
        read: true,
        watch: true,
        send_text: true,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: PI_PROVIDER,
        harness_id: "pi",
        display_name: "Pi",
        list: true,
        read: true,
        watch: true,
        send_text: false,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: NCODE_PROVIDER,
        harness_id: "ncode",
        display_name: "NCode",
        list: true,
        read: true,
        watch: true,
        send_text: true,
        approvals: false,
    },
    LiveThreadSourceDescriptor {
        provider_id: PROXY_HARNESS_PROVIDER,
        harness_id: "proxy-harness",
        display_name: "Proxy Harness",
        list: true,
        read: true,
        watch: true,
        send_text: false,
        approvals: false,
    },
];

pub fn live_thread_source_descriptors() -> &'static [LiveThreadSourceDescriptor] {
    &LIVE_THREAD_SOURCE_DESCRIPTORS
}

pub fn normalize_thread_source_provider(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "claude" | "claude-code" => Some(CLAUDE_PROVIDER),
        "codex" => Some(CODEX_PROVIDER),
        "cursor" => Some(CURSOR_PROVIDER),
        "hermes" | "hermes-agent" => Some(HERMES_PROVIDER),
        "openclaw" | "open-claw" => Some(OPENCLAW_PROVIDER),
        "opencode" | "open-code" => Some(OPENCODE_PROVIDER),
        "pi" => Some(PI_PROVIDER),
        "ncode" | "n-code" | "noumea" | "noumena" | "noumena-code" => Some(NCODE_PROVIDER),
        "proxy-harness" => Some(PROXY_HARNESS_PROVIDER),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSourceSendResult {
    pub conversation_id: String,
    pub message_id: Option<String>,
    pub queued: bool,
    pub deferred: bool,
    pub deferred_reason: Option<String>,
    pub routed: bool,
    pub owner_device_id: Option<String>,
    #[serde(default)]
    pub client_message_id: Option<String>,
    #[serde(default)]
    pub delivery_unknown: bool,
    #[serde(default)]
    pub delivery_error: Option<String>,
}

impl ThreadSourceSendResult {
    pub fn dispatched(conversation_id: String, message_id: String) -> Self {
        Self {
            conversation_id,
            message_id: Some(message_id),
            queued: false,
            deferred: false,
            deferred_reason: None,
            routed: false,
            owner_device_id: None,
            client_message_id: None,
            delivery_unknown: false,
            delivery_error: None,
        }
    }

    pub fn queued(conversation_id: String) -> Self {
        Self {
            conversation_id,
            message_id: None,
            queued: true,
            deferred: false,
            deferred_reason: None,
            routed: false,
            owner_device_id: None,
            client_message_id: None,
            delivery_unknown: false,
            delivery_error: None,
        }
    }

    pub fn deferred(conversation_id: String, reason: impl Into<String>) -> Self {
        Self {
            conversation_id,
            message_id: None,
            queued: false,
            deferred: true,
            deferred_reason: Some(reason.into()),
            routed: false,
            owner_device_id: None,
            client_message_id: None,
            delivery_unknown: false,
            delivery_error: None,
        }
    }

    pub fn unknown(
        conversation_id: String,
        client_message_id: String,
        error: impl Into<String>,
    ) -> Self {
        Self {
            conversation_id,
            message_id: None,
            queued: false,
            deferred: false,
            deferred_reason: None,
            routed: false,
            owner_device_id: None,
            client_message_id: Some(client_message_id),
            delivery_unknown: true,
            delivery_error: Some(error.into()),
        }
    }

    pub fn routed(mut self, owner_device_id: String) -> Self {
        self.routed = true;
        self.owner_device_id = Some(owner_device_id);
        self
    }

    pub fn with_client_message_id(mut self, client_message_id: Option<String>) -> Self {
        self.client_message_id = client_message_id;
        self
    }

    pub fn with_delivery_unknown(mut self, error: impl Into<String>) -> Self {
        self.delivery_unknown = true;
        self.delivery_error = Some(error.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct ThreadSourceApprovalResponseResult {
    pub approval_id: String,
    pub option_id: String,
    pub option_name: String,
    pub conversation_id: String,
    pub response_item_id: String,
}

pub fn thread_source_content_sha256(content: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    encode_hex(&digest)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub version: u8,
    pub request_nonce: String,
    pub requester_device_id: String,
    pub target_device_id: String,
    pub target_mesh_device_id: String,
    pub source_endpoint_id: String,
    pub source_provider: String,
    pub source_id: String,
    pub conversation_id: String,
    pub client_message_id: String,
    pub content_sha256: String,
    pub issued_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeGrant {
    pub version: u8,
    pub challenge_request_id: String,
    pub requester_device_id: String,
    pub target_device_id: String,
    pub target_mesh_device_id: String,
    pub source_endpoint_id: String,
    pub source_provider: String,
    pub source_id: String,
    pub conversation_id: String,
    pub client_message_id: String,
    pub content_sha256: String,
    pub binding_token: String,
    pub nonce: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTextCommand {
    pub version: u8,
    pub challenge_request_id: String,
    pub requester_device_id: String,
    pub target_device_id: String,
    pub target_mesh_device_id: String,
    pub source_endpoint_id: String,
    pub source_provider: String,
    pub source_id: String,
    pub binding_token: String,
    pub nonce: String,
    pub conversation_id: String,
    pub client_message_id: String,
    pub content_sha256: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTextResponse {
    pub version: u8,
    pub challenge_request_id: String,
    pub command_id: String,
    pub requester_device_id: String,
    pub target_device_id: String,
    pub target_mesh_device_id: String,
    pub challenge_nonce: String,
    pub client_message_id: String,
    pub binding_token: String,
    pub result: Option<ThreadSourceSendResult>,
    pub error: Option<String>,
}

/// Open-source adapter interface for syncing and controlling an external CLI
/// agent harness's thread store on any node (macOS, Linux, Raspberry Pi).
pub trait ThreadSourceAdapter: Send + Sync {
    /// Descriptor advertising this adapter's provider id, harness id, and capabilities.
    fn descriptor(&self) -> LiveThreadSourceDescriptor;

    /// Discover lightweight thread index entries on the local machine.
    fn discover_threads(&self) -> Result<Vec<ExternalThreadSummary>, String> {
        Ok(Vec::new())
    }

    /// Send a user prompt into a thread owned by this machine.
    fn send_text(
        &self,
        _source_id: &str,
        _conversation_id: &str,
        _content: &str,
    ) -> Result<ThreadSourceSendResult, String> {
        Err(format!(
            "provider {} does not support send_text",
            self.descriptor().provider_id
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalThreadSummary {
    pub source_provider: String,
    pub source_id: String,
    pub title: Option<String>,
    pub working_directory: Option<String>,
    pub updated_at: String,
}
