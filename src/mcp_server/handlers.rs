use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream;
use rand_core::{OsRng, RngCore};
use tokio::sync::{broadcast, watch};

use crate::mcp_protocol::{JsonRpcRequest, MCP_PROTOCOL_VERSION, ToolCaller, ToolGrant};
use crate::net::gate::{AddressCaller, RequestDeviceId, TunnelPrincipal};
use crate::oauth::ask_proof::PartyScope;

use super::rpc::{
    build_jsonrpc_http_response, build_plain_http_response,
    build_plain_http_response_with_protocol, handle_request,
};
use super::{
    HARNESS_TOOL_POLICY_HEADER, HARNESS_TOOL_POLICY_SEAT, HARNESS_TOOL_POLICY_WRITER,
    McpServerState,
};

fn log_request_metadata(method: &str, path: &str, headers: &HeaderMap) {
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    tracing::trace!(method, path, content_length, "MCP request");
}

fn mint_session_id(session_prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{}{}", session_prefix, hex::encode(bytes))
}

fn is_valid_mcp_date_version(version: &str) -> bool {
    let version = version.trim();
    let bytes = version.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && version >= "2024-11-05"
}

fn clamp_supported_protocol_version(version: &str) -> Option<String> {
    let version = version.trim();
    if !is_valid_mcp_date_version(version) {
        return None;
    }
    if version <= MCP_PROTOCOL_VERSION {
        Some(version.to_string())
    } else {
        Some(MCP_PROTOCOL_VERSION.to_string())
    }
}

fn header_string(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn request_session_id_from_headers(headers: &HeaderMap, session_prefix: &str) -> Option<String> {
    headers
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.starts_with(session_prefix))
        .map(str::to_string)
}

pub(super) async fn store_session_participant(
    state: &Arc<McpServerState>,
    session_id: &str,
    participant_id: &str,
) {
    state
        .session_participants
        .write()
        .await
        .insert(session_id.to_string(), participant_id.to_string());
}

async fn lookup_session_participant(
    state: &Arc<McpServerState>,
    session_id: &str,
) -> Option<String> {
    state
        .session_participants
        .read()
        .await
        .get(session_id)
        .cloned()
}

async fn remove_session_participant(state: &Arc<McpServerState>, session_id: &str) {
    state.session_participants.write().await.remove(session_id);
}

fn tunnel_grant(principal: Option<&TunnelPrincipal>) -> ToolGrant {
    match principal {
        None | Some(TunnelPrincipal::Account) => ToolGrant::Full,
        Some(TunnelPrincipal::OAuth { scope }) => match scope.as_deref() {
            Some(scope) if PartyScope::parse(scope).is_some() => ToolGrant::Nothing,
            _ => ToolGrant::Seat,
        },
    }
}

fn requested_grant(requested_policy: Option<&str>) -> ToolGrant {
    match requested_policy {
        Some(HARNESS_TOOL_POLICY_SEAT) => ToolGrant::Seat,
        Some(HARNESS_TOOL_POLICY_WRITER) => ToolGrant::Writer,
        Some(policy) => {
            tracing::debug!(policy, "MCP tool policy header not recognized; ignoring it");
            ToolGrant::Full
        }
        None => ToolGrant::Full,
    }
}

fn combined_grant(tunnel: ToolGrant, participant: ToolGrant, requested: ToolGrant) -> ToolGrant {
    tunnel.narrowed_to(participant).narrowed_to(requested)
}

async fn caller_grant(
    state: &Arc<McpServerState>,
    tunnel_principal: Option<&TunnelPrincipal>,
    participant_id: Option<&str>,
    requested_policy: Option<&str>,
) -> ToolGrant {
    let participant = match participant_id {
        Some(participant_id) => {
            let surface = Arc::clone(&state.surface);
            let participant_id = participant_id.to_string();
            tokio::task::spawn_blocking(move || surface.participant_grant(&participant_id))
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "participant grant lookup failed; granting seat surface");
                    ToolGrant::Seat
                })
        }
        None => ToolGrant::Full,
    };
    combined_grant(
        tunnel_grant(tunnel_principal),
        participant,
        requested_grant(requested_policy),
    )
}

async fn resolve_participant_from_agent(
    state: &Arc<McpServerState>,
    session_id: Option<&str>,
    agent_id: Option<&str>,
    refresh_from_pid_event: bool,
) -> Result<Option<String>, String> {
    let Some(agent_id) = agent_id else {
        return Ok(None);
    };
    let Some(agent) = state
        .resolver
        .resolve_runtime_agent(agent_id, refresh_from_pid_event)
    else {
        return Ok(None);
    };
    match state.surface.participant_for_runtime_agent(&agent)? {
        Some(resolved_participant_id) => {
            if let Some(session_id) = session_id {
                store_session_participant(state, session_id, &resolved_participant_id).await;
            }
            Ok(Some(resolved_participant_id))
        }
        None => Ok(None),
    }
}

enum SsePhase {
    Initial,
    Running,
}

fn sse_stream_response(
    state: Arc<McpServerState>,
    headers: &HeaderMap,
    initial_endpoint: Option<String>,
) -> Response {
    let stream_session_id = request_session_id_from_headers(headers, state.session_prefix);
    let rx = state.event_tx.subscribe();
    let shutdown = state.shutdown.clone();

    let sse_stream = stream::unfold(
        (
            SsePhase::Initial,
            initial_endpoint,
            rx,
            shutdown,
            state,
            stream_session_id,
        ),
        |(phase, mut endpoint, rx, shutdown, state, stream_session_id)| async move {
            match phase {
                SsePhase::Initial => {
                    if let Some(endpoint_url) = endpoint.take() {
                        let ev = Ok::<Event, Infallible>(
                            Event::default().event("endpoint").data(endpoint_url),
                        );
                        return Some((
                            ev,
                            (
                                SsePhase::Running,
                                None,
                                rx,
                                shutdown,
                                state,
                                stream_session_id,
                            ),
                        ));
                    }
                    sse_next_event(rx, shutdown, state, stream_session_id).await
                }
                SsePhase::Running => sse_next_event(rx, shutdown, state, stream_session_id).await,
            }
        },
    );

    let mut response = IntoResponse::into_response(
        Sse::new(sse_stream).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        ),
    );
    response.headers_mut().insert(
        "MCP-Protocol-Version",
        HeaderValue::from_static(MCP_PROTOCOL_VERSION),
    );
    response
}

async fn sse_next_event(
    mut rx: broadcast::Receiver<String>,
    mut shutdown: watch::Receiver<bool>,
    state: Arc<McpServerState>,
    stream_session_id: Option<String>,
) -> Option<(
    Result<Event, Infallible>,
    (
        SsePhase,
        Option<String>,
        broadcast::Receiver<String>,
        watch::Receiver<bool>,
        Arc<McpServerState>,
        Option<String>,
    ),
)> {
    loop {
        if *shutdown.borrow() {
            if let Some(session_id) = stream_session_id.as_deref() {
                remove_session_participant(&state, session_id).await;
            }
            return None;
        }
        let event = tokio::select! {
            _ = shutdown.changed() => {
                if let Some(session_id) = stream_session_id.as_deref() {
                    remove_session_participant(&state, session_id).await;
                }
                return None;
            }
            event = rx.recv() => event,
        };
        match event {
            Ok(data) => {
                if data.contains("tools/list_changed") {
                    tracing::trace!("SSE: emitting tools/list_changed to connected client");
                }
                let ev = Ok::<Event, Infallible>(Event::default().event("message").data(data));
                return Some((
                    ev,
                    (
                        SsePhase::Running,
                        None,
                        rx,
                        shutdown,
                        state,
                        stream_session_id,
                    ),
                ));
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => {
                if let Some(session_id) = stream_session_id.as_deref() {
                    remove_session_participant(&state, session_id).await;
                }
                return None;
            }
        }
    }
}

pub async fn get_message_handler(
    State(state): State<Arc<McpServerState>>,
    req: Request<Body>,
) -> Response {
    log_request_metadata("GET", &state.mcp_endpoint_path, req.headers());
    sse_stream_response(state, req.headers(), None)
}

pub async fn sse_handler(State(state): State<Arc<McpServerState>>, req: Request<Body>) -> Response {
    log_request_metadata("GET", &state.sse_endpoint_path, req.headers());
    let endpoint_url = format!("http://localhost:{}{}", state.port, state.mcp_endpoint_path);
    sse_stream_response(state, req.headers(), Some(endpoint_url))
}

fn lock_error_response(context: &str) -> Response {
    tracing::error!("{context}");
    build_plain_http_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        Body::from("Session state lock error"),
    )
}

#[allow(clippy::result_large_err)]
fn resolve_or_recover_session_protocol(
    state: &McpServerState,
    sid: &str,
    mcp_protocol_version: Option<&str>,
    method: &str,
) -> Result<String, Response> {
    let newly_inserted = state
        .initialized_sessions
        .lock()
        .map_err(|_| lock_error_response("Failed to lock MCP initialized sessions"))?
        .insert(sid.to_string());
    if newly_inserted {
        tracing::debug!(session_id = %sid, method = %method, "Recovering unknown MCP session");
        let recovered = mcp_protocol_version
            .and_then(clamp_supported_protocol_version)
            .unwrap_or_else(|| "2025-03-26".to_string());
        state
            .session_protocol_versions
            .lock()
            .map_err(|_| {
                lock_error_response("Failed to lock MCP session protocol versions for recovery")
            })?
            .insert(sid.to_string(), recovered);
    }

    let expected = state
        .session_protocol_versions
        .lock()
        .map_err(|_| lock_error_response("Failed to lock MCP session protocol versions"))?
        .get(sid)
        .cloned()
        .ok_or_else(|| {
            tracing::error!(
                session_id = %sid,
                "Missing stored MCP protocol version for initialized session"
            );
            build_plain_http_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("Missing protocol version for initialized session"),
            )
        })?;

    if let Some(version) = mcp_protocol_version.filter(|v| *v != expected) {
        let clamped_matches =
            clamp_supported_protocol_version(version).is_some_and(|clamped| clamped == expected);
        if !clamped_matches {
            tracing::warn!(got = %version, expected = %expected, "Invalid MCP-Protocol-Version header");
            return Err(build_plain_http_response(
                StatusCode::BAD_REQUEST,
                Body::from(format!(
                    "Invalid or unsupported MCP-Protocol-Version: {version}"
                )),
            ));
        }
    }

    Ok(expected)
}

#[allow(clippy::result_large_err)]
fn record_initialized_session(
    state: &McpServerState,
    session_id: &str,
    protocol_version: &str,
    agent_id: Option<&str>,
) -> Result<(), Response> {
    state
        .initialized_sessions
        .lock()
        .map_err(|_| lock_error_response("Failed to lock MCP initialized sessions for update"))?
        .insert(session_id.to_string());
    state
        .session_protocol_versions
        .lock()
        .map_err(|_| {
            lock_error_response("Failed to lock MCP session protocol versions for update")
        })?
        .insert(session_id.to_string(), protocol_version.to_string());
    if let Some(agent_id) = agent_id {
        state
            .session_agent_ids
            .lock()
            .map_err(|_| lock_error_response("Failed to lock MCP session agent IDs for update"))?
            .insert(session_id.to_string(), agent_id.to_string());
    }
    Ok(())
}

pub async fn message_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<McpServerState>>,
    req: Request<Body>,
) -> Response {
    log_request_metadata("POST", &state.mcp_endpoint_path, req.headers());

    let agent_id_from_header = header_string(req.headers(), "X-Proxy-Agent-Id");
    let participant_id_from_header = header_string(req.headers(), "X-Proxy-Participant-Id");
    let requested_policy = header_string(req.headers(), HARNESS_TOOL_POLICY_HEADER);
    let tunnel_principal = req.extensions().get::<TunnelPrincipal>().cloned();
    let device_id = req
        .extensions()
        .get::<RequestDeviceId>()
        .map(|RequestDeviceId(id)| *id);
    let address_caller = req.extensions().get::<AddressCaller>().copied();

    let request_session_id = request_session_id_from_headers(req.headers(), state.session_prefix);
    let mcp_protocol_version = header_string(req.headers(), "MCP-Protocol-Version");
    let accepts_sse = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains("text/event-stream"));

    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to read MCP request body");
            return build_plain_http_response(
                StatusCode::BAD_REQUEST,
                Body::from("Failed to read request body"),
            );
        }
    };

    let request: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse MCP JSON-RPC request");
            return build_plain_http_response(
                StatusCode::BAD_REQUEST,
                Body::from(format!("Failed to parse JSON: {e}")),
            );
        }
    };

    let request_method = request.method.clone();
    let request_id_for_log = request.id.clone();
    let is_initialize = request.method == "initialize";
    let is_notification = request.id.is_none();
    let session_id = (!is_initialize).then_some(request_session_id).flatten();

    let request_protocol_version = if is_initialize {
        None
    } else if let Some(sid) = session_id.as_ref() {
        match resolve_or_recover_session_protocol(
            &state,
            sid,
            mcp_protocol_version.as_deref(),
            &request.method,
        ) {
            Ok(version) => Some(version),
            Err(response) => return response,
        }
    } else {
        match mcp_protocol_version.as_deref() {
            Some(version) => match clamp_supported_protocol_version(version) {
                Some(clamped) => Some(clamped),
                None => {
                    tracing::warn!(got = %version, latest_supported = MCP_PROTOCOL_VERSION, "Invalid MCP-Protocol-Version header");
                    return build_plain_http_response(
                        StatusCode::BAD_REQUEST,
                        Body::from(format!(
                            "Invalid or unsupported MCP-Protocol-Version: {version}"
                        )),
                    );
                }
            },
            None => {
                tracing::debug!(
                    assumed_protocol_version = "2025-03-26",
                    "Missing MCP-Protocol-Version header"
                );
                Some("2025-03-26".to_string())
            }
        }
    };

    let mut agent_id_from_session = false;
    let mut agent_id = if let Some(id) = agent_id_from_header {
        Some(id)
    } else if let Some(session_id) = session_id.as_ref() {
        let mapped_agent_id = match state.session_agent_ids.lock() {
            Ok(ids) => ids.get(session_id).cloned(),
            Err(_) => return lock_error_response("Failed to lock MCP session agent IDs"),
        };
        agent_id_from_session = mapped_agent_id.is_some();
        mapped_agent_id
    } else if is_initialize {
        let client_port = addr.port();
        state
            .resolver
            .correlate_agent_by_port(client_port)
            .map(|(pid, id)| {
                tracing::trace!(agent_id = %id, pid, "MCP client registered agent by PID");
                id
            })
    } else {
        None
    };

    if !is_initialize && agent_id.is_none() {
        if let Some(session_id) = session_id.as_ref() {
            if let Some((pid, adopted_agent_id)) =
                state.resolver.correlate_agent_by_port(addr.port())
            {
                if let Ok(mut session_agent_ids) = state.session_agent_ids.lock() {
                    session_agent_ids.insert(session_id.clone(), adopted_agent_id.clone());
                }
                tracing::debug!(session_id = %session_id, agent_id = %adopted_agent_id, pid, "Adopted unknown MCP session via TCP/PID correlation");
                agent_id_from_session = true;
                agent_id = Some(adopted_agent_id);
            }
        }
    }

    let mut participant_id = if let Some(participant_id) = participant_id_from_header.clone() {
        if let Some(session_id) = session_id.as_deref() {
            store_session_participant(&state, session_id, &participant_id).await;
        }
        Some(participant_id)
    } else if let Some(session_id) = session_id.as_deref() {
        lookup_session_participant(&state, session_id).await
    } else {
        None
    };

    if participant_id.is_none() {
        let refresh_from_pid_event = !is_initialize && agent_id_from_session;
        match resolve_participant_from_agent(
            &state,
            session_id.as_deref(),
            agent_id.as_deref(),
            refresh_from_pid_event,
        )
        .await
        {
            Ok(resolved_participant_id) => participant_id = resolved_participant_id,
            Err(error) => {
                tracing::warn!(agent_id = ?agent_id, %error, "Failed to resolve MCP participant from runtime agent; continuing unattributed");
            }
        }
    }

    let response_session_id = is_initialize.then(|| mint_session_id(state.session_prefix));
    let grant = caller_grant(
        &state,
        tunnel_principal.as_ref(),
        participant_id.as_deref(),
        requested_policy.as_deref(),
    )
    .await;
    let caller = tool_caller(address_caller, grant);

    let response = handle_request(
        &state,
        request,
        agent_id.clone(),
        participant_id,
        grant,
        caller,
        session_id.clone(),
        device_id,
    )
    .await;
    if let Some(error) = response.error.as_ref() {
        tracing::warn!(
            method = %request_method,
            request_id = ?request_id_for_log,
            accepts_sse,
            is_notification,
            error_code = error.code,
            error_message = %error.message,
            "MCP request handled with error"
        );
    } else {
        tracing::trace!(method = %request_method, request_id = ?request_id_for_log, accepts_sse, is_notification, "MCP request handled");
    }
    let response_protocol_version = if is_initialize {
        response
            .result
            .as_ref()
            .and_then(|result| result.get("protocolVersion"))
            .and_then(|v| v.as_str())
            .unwrap_or(MCP_PROTOCOL_VERSION)
            .to_string()
    } else {
        request_protocol_version.unwrap_or_else(|| MCP_PROTOCOL_VERSION.to_string())
    };

    let initialize_succeeded = is_initialize && response.error.is_none();
    if initialize_succeeded {
        if let Some(session_id) = response_session_id.as_ref() {
            if let Err(response) = record_initialized_session(
                &state,
                session_id,
                &response_protocol_version,
                agent_id.as_deref(),
            ) {
                return response;
            }
            if let Some(participant_id) = participant_id_from_header.as_deref() {
                store_session_participant(&state, session_id, participant_id).await;
            }
        }
    }
    if is_notification {
        build_plain_http_response_with_protocol(
            StatusCode::ACCEPTED,
            Body::empty(),
            &response_protocol_version,
        )
    } else {
        build_jsonrpc_http_response(
            response,
            accepts_sse,
            initialize_succeeded
                .then_some(response_session_id.as_deref())
                .flatten(),
            &response_protocol_version,
        )
    }
}

fn tool_caller(address: Option<AddressCaller>, grant: ToolGrant) -> ToolCaller {
    match address {
        Some(address) => ToolCaller::Address {
            owner_proven: address.owner_proven,
        },
        None if grant != ToolGrant::Full => ToolCaller::Agent,
        None => ToolCaller::Owner,
    }
}
