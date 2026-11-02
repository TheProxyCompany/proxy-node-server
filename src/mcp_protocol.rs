//! Model Context Protocol (MCP) JSON-RPC 2.0 wire types, tool grants, and catalog models.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolAvailability {
    Always,
    Participant,
    Moderator,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    pub availability: ToolAvailability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolGrant {
    Nothing,
    Seat,
    Writer,
    Full,
}

impl ToolGrant {
    pub fn narrowed_to(self, other: ToolGrant) -> ToolGrant {
        self.min(other)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum McpMessage {
    #[serde(rename = "request")]
    Request(JsonRpcRequest),
    #[serde(rename = "response")]
    Response(JsonRpcResponse),
    #[serde(rename = "notification")]
    Notification {
        method: String,
        params: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completions: Option<CompletionsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TasksCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            tools: Some(ToolsCapability {
                list_changed: Some(true),
            }),
            resources: Some(ResourcesCapability {
                subscribe: Some(true),
                list_changed: Some(true),
            }),
            prompts: Some(PromptsCapability {
                list_changed: Some(true),
            }),
            logging: Some(LoggingCapability {}),
            completions: Some(CompletionsCapability {}),
            tasks: Some(TasksCapability {
                list: Some(TasksListCapability {}),
                cancel: Some(TasksCancelCapability {}),
                requests: Some(TasksRequestsCapability {
                    tools: Some(TasksRequestsToolsCapability {
                        call: Some(TasksRequestsToolsCallCapability {}),
                    }),
                }),
            }),
            experimental: Some(serde_json::json!({})),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesCapability {
    pub subscribe: Option<bool>,
    #[serde(rename = "listChanged")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingCapability {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionsCapability {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksCapability {
    pub list: Option<TasksListCapability>,
    pub cancel: Option<TasksCancelCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests: Option<TasksRequestsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksListCapability {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksCancelCapability {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksRequestsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<TasksRequestsToolsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksRequestsToolsCapability {
    pub call: Option<TasksRequestsToolsCallCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksRequestsToolsCallCapability {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "proxy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: Some(
                "Proxy's local coordination layer - agents, graph, content, MCP tools".to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

impl Default for InitializeResult {
    fn default() -> Self {
        Self {
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo::default(),
            instructions: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    pub annotations: Value,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolCaller {
    Owner,
    #[default]
    Agent,
    Address {
        owner_proven: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    pub name: String,
    pub arguments: Option<Value>,
    #[serde(skip)]
    pub caller: ToolCaller,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    #[serde(rename = "structuredContent", skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image {
        data: String,
        #[serde(rename = "mimeType", alias = "mime_type")]
        mime_type: String,
    },
    #[serde(rename = "resource")]
    Resource { resource: Value },
}

impl ToolCallResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            structured_content: None,
            is_error: None,
        }
    }

    pub fn success(data: Value) -> Self {
        Self {
            content: vec![ToolContent::Text {
                text: data.to_string(),
            }],
            structured_content: None,
            is_error: None,
        }
    }

    pub fn structured(data: Value) -> Self {
        let text = data.to_string();
        Self::text_and_structured(text, data)
    }

    pub fn text_and_structured(text: impl Into<String>, data: Value) -> Self {
        let structured = match data {
            Value::Object(_) => data,
            Value::Array(_) => serde_json::json!({ "items": data }),
            other => serde_json::json!({ "value": other }),
        };
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            structured_content: Some(structured),
            is_error: None,
        }
    }

    pub fn error_text(message: String) -> Self {
        Self {
            content: vec![ToolContent::Text { text: message }],
            structured_content: None,
            is_error: Some(true),
        }
    }
}
