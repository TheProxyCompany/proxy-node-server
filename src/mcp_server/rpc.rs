use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use serde_json::Value;

use crate::identity::DeviceId;
use crate::mcp_protocol::{
    InitializeParams, InitializeResult, JsonRpcRequest, JsonRpcResponse, MCP_PROTOCOL_VERSION,
    ServerInfo, ToolCallRequest, ToolCallResult, ToolCaller, ToolGrant,
};

use super::handlers::store_session_participant;
use super::{McpServerState, PARTY_JOIN_TOOL};

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_request(
    state: &Arc<McpServerState>,
    request: JsonRpcRequest,
    agent_id: Option<String>,
    participant_id: Option<String>,
    grant: ToolGrant,
    caller: ToolCaller,
    session_id: Option<String>,
    device_id: Option<DeviceId>,
) -> JsonRpcResponse {
    match request.method.as_str() {
        "initialize" => handle_initialize(
            request.id,
            request.params,
            state.server_info.clone(),
            state.surface.instructions(),
        ),
        "initialized" | "notifications/initialized" => {
            JsonRpcResponse::success(request.id, serde_json::json!({}))
        }
        "tools/list" => handle_tools_list(state, request.id, participant_id.as_deref(), grant),
        "tools/call" => {
            handle_tools_call(
                state,
                request,
                agent_id,
                participant_id,
                grant,
                caller,
                session_id,
                device_id,
            )
            .await
        }
        "resources/list" => {
            JsonRpcResponse::success(request.id, serde_json::json!({ "resources": [] }))
        }
        "resources/templates/list" => {
            JsonRpcResponse::success(request.id, serde_json::json!({ "resourceTemplates": [] }))
        }
        "prompts/list" => {
            JsonRpcResponse::success(request.id, serde_json::json!({ "prompts": [] }))
        }
        "resources/read"
        | "resources/subscribe"
        | "resources/unsubscribe"
        | "prompts/get"
        | "logging/setLevel"
        | "completion/complete"
        | "tasks/list"
        | "tasks/get"
        | "tasks/result"
        | "tasks/cancel" => JsonRpcResponse::error(
            request.id,
            -32601,
            &format!("{}: not yet implemented", request.method),
        ),
        "ping" => JsonRpcResponse::success(request.id, serde_json::json!({})),
        _ => JsonRpcResponse::error(
            request.id,
            -32601,
            &format!("Method not found: {}", request.method),
        ),
    }
}

fn handle_initialize(
    id: Option<Value>,
    params: Option<Value>,
    server_info: ServerInfo,
    instructions: Option<&'static str>,
) -> JsonRpcResponse {
    let client_protocol_version = params
        .and_then(|p| serde_json::from_value::<InitializeParams>(p).ok())
        .and_then(|p| p.protocol_version);

    let negotiated_protocol_version = client_protocol_version
        .as_deref()
        .filter(|v| *v < MCP_PROTOCOL_VERSION)
        .unwrap_or(MCP_PROTOCOL_VERSION)
        .to_string();

    let result = InitializeResult {
        protocol_version: negotiated_protocol_version,
        server_info,
        instructions: instructions.map(str::to_string),
        ..Default::default()
    };
    match serde_json::to_value(result) {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err(err) => JsonRpcResponse::error(
            id,
            -32603,
            &format!("Failed to serialize initialize response: {err}"),
        ),
    }
}

pub(super) fn build_jsonrpc_http_response(
    response: JsonRpcResponse,
    accepts_sse: bool,
    session_id: Option<&str>,
    protocol_version: &str,
) -> Response {
    let response_json = match serde_json::to_string(&response) {
        Ok(value) => value,
        Err(err) => {
            return build_plain_http_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from(format!("Failed to serialize response: {err}")),
            );
        }
    };

    let mut builder = Response::builder().header("MCP-Protocol-Version", protocol_version);
    if let Some(session_id) = session_id {
        builder = builder.header("Mcp-Session-Id", session_id);
    }

    let (content_type, body) = if accepts_sse {
        builder = builder.header(header::CACHE_CONTROL, "no-cache");
        (
            "text/event-stream",
            format!("event: message\ndata: {response_json}\n\n"),
        )
    } else {
        ("application/json", response_json)
    };

    builder
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap_or_else(|err| {
            build_plain_http_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from(format!("Failed to build response: {err}")),
            )
        })
}

pub(super) fn build_plain_http_response(status: StatusCode, body: Body) -> Response {
    build_plain_http_response_with_protocol(status, body, MCP_PROTOCOL_VERSION)
}

pub(super) fn build_plain_http_response_with_protocol(
    status: StatusCode,
    body: Body,
    protocol_version: &str,
) -> Response {
    match Response::builder()
        .status(status)
        .header("MCP-Protocol-Version", protocol_version)
        .body(body)
    {
        Ok(response) => response,
        Err(_) => {
            let mut response = Response::new(Body::from("Internal server error"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(
                "MCP-Protocol-Version",
                HeaderValue::from_str(protocol_version)
                    .unwrap_or_else(|_| HeaderValue::from_static(MCP_PROTOCOL_VERSION)),
            );
            response
        }
    }
}

fn handle_tools_list(
    state: &McpServerState,
    id: Option<Value>,
    participant_id: Option<&str>,
    grant: ToolGrant,
) -> JsonRpcResponse {
    let mut tools = state.surface.tools_for_participant(participant_id);
    if grant != ToolGrant::Full {
        let offered = tools.len();
        tools.retain(|tool| {
            state
                .surface
                .participant_may_call(participant_id, grant, &tool.name)
        });
        tracing::trace!(
            offered,
            listed = tools.len(),
            ?grant,
            "tools/list scoped to grant"
        );
    }
    JsonRpcResponse::success(id, serde_json::json!({ "tools": tools }))
}

#[allow(clippy::too_many_arguments)]
async fn handle_tools_call(
    state: &Arc<McpServerState>,
    request: JsonRpcRequest,
    agent_id: Option<String>,
    participant_id: Option<String>,
    grant: ToolGrant,
    caller: ToolCaller,
    session_id: Option<String>,
    device_id: Option<DeviceId>,
) -> JsonRpcResponse {
    let request_id = request.id.clone();
    let Some(params) = request.params else {
        return JsonRpcResponse::error(request.id, -32602, "Missing params");
    };

    let mut call: ToolCallRequest = match serde_json::from_value(params) {
        Ok(c) => c,
        Err(e) => {
            return JsonRpcResponse::error(request.id, -32602, &format!("Invalid params: {e}"));
        }
    };
    call.caller = if matches!(caller, ToolCaller::Agent)
        && state
            .surface
            .participant_may_call(participant_id.as_deref(), grant, "proxy_make_move")
    {
        ToolCaller::Owner
    } else {
        caller
    };

    if !state
        .surface
        .participant_may_call(participant_id.as_deref(), grant, &call.name)
    {
        tracing::info!(?request_id, tool_name = %call.name, ?participant_id, ?grant, "MCP tools/call refused: outside grant");
        let msg = state.resolver.sanitize_error(format!(
            "{} is not open to this connection. Only the tools in tools/list are.",
            call.name
        ));
        return tool_result_response(request.id, ToolCallResult::error_text(msg));
    }

    tracing::info!(
        ?request_id,
        tool_name = %call.name,
        ?agent_id,
        ?participant_id,
        device_id = device_id.map(|id| id.to_hex()),
        has_arguments = call.arguments.is_some(),
        "MCP tools/call start"
    );
    let result = state
        .surface
        .handle_tool_call(&call, agent_id, participant_id)
        .await;
    if call.name == PARTY_JOIN_TOOL && result.is_error != Some(true) {
        if let (Some(session_id), Some(joined_participant_id)) = (
            session_id.as_deref(),
            result
                .structured_content
                .as_ref()
                .and_then(|payload| payload.get("participant_id"))
                .and_then(Value::as_str),
        ) {
            store_session_participant(state, session_id, joined_participant_id).await;
        }
    }
    tracing::info!(
        ?request_id,
        tool_name = %call.name,
        is_error = result.is_error.unwrap_or(false),
        content_count = result.content.len(),
        structured_content = result.structured_content.is_some(),
        "MCP tools/call completed"
    );
    tool_result_response(request.id, result)
}

fn tool_result_response(id: Option<Value>, result: ToolCallResult) -> JsonRpcResponse {
    match serde_json::to_value(result) {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err(err) => JsonRpcResponse::error(
            id,
            -32603,
            &format!("Failed to serialize tool result: {err}"),
        ),
    }
}
