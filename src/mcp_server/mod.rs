//! Generic MCP HTTP/SSE server transport (`McpToolSurface`, `McpAgentResolver`,
//! `McpServerState`, `surface_router`) for mounting any MCP tool surface on an
//! Axum router without coupling `proxy-node-server` to application internals.

mod handlers;
mod rpc;
pub use handlers::{get_message_handler, message_handler, sse_handler};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    routing::{get, post},
};
use tokio::sync::{RwLock, broadcast, watch};

use crate::mcp_protocol::{
    CatalogTool, ServerInfo, ToolAvailability, ToolCallRequest, ToolCallResult, ToolDefinition,
    ToolGrant,
};

pub const HARNESS_TOOL_POLICY_HEADER: &str = "X-Proxy-Tool-Policy";
pub const HARNESS_TOOL_POLICY_SEAT: &str = "seat";
pub const HARNESS_TOOL_POLICY_WRITER: &str = "writer";
pub const PARTY_JOIN_TOOL: &str = "party_join";

/// Minimal runtime agent descriptor passed to [`McpToolSurface::participant_for_runtime_agent`].
#[derive(Debug, Clone)]
pub struct RuntimeAgentInfo {
    pub id: String,
    pub harness: String,
    pub harness_id: Option<String>,
    pub pid: Option<i32>,
}

pub fn runtime_source_provider(harness: &str) -> Option<&'static str> {
    match harness {
        "claude-code" | "claude_code" => Some("claude_code"),
        "codex" => Some("codex"),
        "hermes" | "hermes-agent" => Some("hermes"),
        _ => None,
    }
}

/// Pluggable host callback for correlating local TCP ports / PIDs to runtime agents.
pub trait McpAgentResolver: Send + Sync + 'static {
    fn correlate_agent_by_port(&self, client_port: u16) -> Option<(i32, String)> {
        let _ = client_port;
        None
    }

    fn resolve_runtime_agent(
        &self,
        agent_id: &str,
        refresh_from_pid_event: bool,
    ) -> Option<RuntimeAgentInfo> {
        let _ = (agent_id, refresh_from_pid_event);
        None
    }

    fn sanitize_error(&self, message: String) -> String {
        message
    }
}

/// Default no-op resolver for standalone node servers.
pub struct NoopMcpAgentResolver;
impl McpAgentResolver for NoopMcpAgentResolver {}

/// Surface-specific tool catalog + dispatcher used by the MCP HTTP/SSE transport.
#[async_trait]
pub trait McpToolSurface: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn session_prefix(&self) -> &'static str;
    fn server_info(&self) -> ServerInfo;

    fn instructions(&self) -> Option<&'static str> {
        None
    }

    fn all_tools(&self) -> Vec<ToolDefinition>;

    fn tools_for_participant(&self, participant_id: Option<&str>) -> Vec<ToolDefinition> {
        let _ = participant_id;
        self.all_tools()
    }

    fn harness_seat_may_call(&self, tool_name: &str) -> bool {
        let _ = tool_name;
        true
    }

    fn map_writer_may_call(&self, tool_name: &str) -> bool {
        self.harness_seat_may_call(tool_name)
    }

    fn participant_grant(&self, participant_id: &str) -> ToolGrant {
        let _ = participant_id;
        ToolGrant::Full
    }

    fn grant_allows(&self, grant: ToolGrant, tool_name: &str) -> bool {
        match grant {
            ToolGrant::Full => true,
            ToolGrant::Writer => self.map_writer_may_call(tool_name),
            ToolGrant::Seat => self.harness_seat_may_call(tool_name),
            ToolGrant::Nothing => false,
        }
    }

    fn participant_may_call(
        &self,
        participant_id: Option<&str>,
        grant: ToolGrant,
        tool_name: &str,
    ) -> bool {
        let _ = participant_id;
        self.grant_allows(grant, tool_name)
    }

    fn tool_availability(&self, _tool_name: &str) -> ToolAvailability {
        ToolAvailability::Always
    }

    fn catalog(&self) -> Vec<CatalogTool> {
        self.all_tools()
            .into_iter()
            .map(|def| {
                let availability = self.tool_availability(&def.name);
                CatalogTool {
                    name: def.name,
                    title: def.title,
                    description: Some(def.description).filter(|d| !d.is_empty()),
                    input_schema: def.input_schema,
                    availability,
                }
            })
            .collect()
    }

    fn participant_for_runtime_agent(
        &self,
        agent: &RuntimeAgentInfo,
    ) -> Result<Option<String>, String> {
        let _ = agent;
        Ok(None)
    }

    fn attach_event_tx(&self, event_tx: broadcast::Sender<String>) {
        let _ = event_tx;
    }

    async fn handle_tool_call(
        &self,
        call: &ToolCallRequest,
        agent_id: Option<String>,
        participant_id: Option<String>,
    ) -> ToolCallResult;
}

/// Per-surface HTTP/SSE transport state.
pub struct McpServerState {
    pub event_tx: broadcast::Sender<String>,
    pub resolver: Arc<dyn McpAgentResolver>,
    pub surface: Arc<dyn McpToolSurface>,
    pub initialized_sessions: Mutex<HashSet<String>>,
    pub session_protocol_versions: Mutex<HashMap<String, String>>,
    pub session_agent_ids: Mutex<HashMap<String, String>>,
    pub session_participants: Arc<RwLock<HashMap<String, String>>>,
    pub session_prefix: &'static str,
    pub server_info: ServerInfo,
    pub port: u16,
    pub mcp_endpoint_path: String,
    pub sse_endpoint_path: String,
    pub shutdown: watch::Receiver<bool>,
}

pub fn build_surface_state(
    port: u16,
    resolver: Arc<dyn McpAgentResolver>,
    surface: Arc<dyn McpToolSurface>,
    mcp_endpoint_path: String,
    sse_endpoint_path: String,
    shutdown: watch::Receiver<bool>,
) -> Arc<McpServerState> {
    let (event_tx, _) = broadcast::channel(100);
    surface.attach_event_tx(event_tx.clone());
    let session_prefix = surface.session_prefix();
    let server_info = surface.server_info();

    Arc::new(McpServerState {
        event_tx,
        resolver,
        surface,
        initialized_sessions: Mutex::new(HashSet::new()),
        session_protocol_versions: Mutex::new(HashMap::new()),
        session_agent_ids: Mutex::new(HashMap::new()),
        session_participants: Arc::new(RwLock::new(HashMap::new())),
        session_prefix,
        server_info,
        port,
        mcp_endpoint_path,
        sse_endpoint_path,
        shutdown,
    })
}

pub fn surface_router(state: Arc<McpServerState>) -> Router {
    Router::new()
        .route(
            "/",
            post(handlers::message_handler).get(handlers::get_message_handler),
        )
        .route("/sse", get(handlers::sse_handler))
        .with_state(state)
}
