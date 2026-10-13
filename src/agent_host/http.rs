//! Mount these routes on the node's existing HTTP server. The embedding node
//! supplies its existing address authority; there is no second bearer system.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{
    IntoResponse, Response, Sse,
    sse::{Event, KeepAlive},
};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::{AgentHost, AgentInput, HostError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOperation {
    Read,
    Write,
}

/// Called for the exact named agent and operation on every request and while
/// streaming. The implementation must verify the node's account/OAuth/purpose
/// grant. Possessing an unrelated party or agent token must not open this one.
pub trait HostAuthority: Send + Sync {
    fn authorize(
        &self,
        headers: &HeaderMap,
        agent_id: &str,
        operation: HostOperation,
    ) -> Result<(), HostError>;
}

impl<F> HostAuthority for F
where
    F: Fn(&HeaderMap, &str, HostOperation) -> Result<(), HostError> + Send + Sync,
{
    fn authorize(
        &self,
        headers: &HeaderMap,
        agent_id: &str,
        operation: HostOperation,
    ) -> Result<(), HostError> {
        self(headers, agent_id, operation)
    }
}

#[derive(Clone)]
struct HttpState {
    host: AgentHost,
    authority: Arc<dyn HostAuthority>,
}

pub fn router(host: AgentHost, authority: Arc<dyn HostAuthority>) -> Router {
    api_router(host.clone(), authority.clone()).merge(
        Router::new()
            .route("/{agent}", get(attach))
            .with_state(HttpState { host, authority }),
    )
}

pub fn api_router(host: AgentHost, authority: Arc<dyn HostAuthority>) -> Router {
    Router::new()
        .route("/client/agents/{agent}", get(attach))
        .route("/client/agents/{agent}/input", post(input))
        .route("/client/agents/{agent}/status", get(status))
        .route("/client/agents/{agent}/events", get(events))
        .route("/client/agents/{agent}/abort", post(abort))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(HttpState { host, authority })
}

impl IntoResponse for HostError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Busy => StatusCode::CONFLICT,
            Self::AcceptanceUnknown => StatusCode::GATEWAY_TIMEOUT,
            Self::Rejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        // OS errors can disclose local paths. Keep those on the trusted side.
        let message = if matches!(self, Self::Io(_) | Self::Json(_)) {
            "agent host could not complete the request".to_string()
        } else {
            self.to_string()
        };
        (status, Json(json!({"error":message}))).into_response()
    }
}

async fn input(
    State(s): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<AgentInput>,
) -> Result<Response, HostError> {
    s.authority.authorize(&headers, &id, HostOperation::Write)?;
    // A remote caller cannot label its payload a human decision or local UI
    // event. Grant checks happen outside message text and correlation fields.
    input.source = Some("address-client".into());
    let descriptor = s.host.descriptor(&id)?;
    input.conversation_id = descriptor.conversation_id;
    input.participant_id = descriptor.participant_id;
    input.task_id = descriptor.task_id;
    let accepted = s.host.submit(&id, input).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)).into_response())
}

async fn status(
    State(s): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HostError> {
    s.authority.authorize(&headers, &id, HostOperation::Read)?;
    Ok(Json(s.host.status(&id).await?).into_response())
}

async fn attach(
    State(s): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HostError> {
    s.authority.authorize(&headers, &id, HostOperation::Read)?;
    let status = s.host.status(&id).await?;
    Ok(Json(
        json!({"agent_id":id,"runtime":"proxy-harness","status":status,
        "input":format!("/client/agents/{id}/input"),"events":format!("/client/agents/{id}/events"),
        "durable_acceptance":"accepted event after runtime journal sync",
        "disconnect":"detaches this client; the hosted process continues"}),
    )
    .into_response())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbortInput {
    input_id: Option<String>,
}

async fn abort(
    State(s): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HostError> {
    s.authority.authorize(&headers, &id, HostOperation::Write)?;
    let input: AbortInput = if body.is_empty() {
        AbortInput::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| HostError::Invalid("invalid abort input".into()))?
    };
    match input.input_id {
        Some(input_id) => s.host.abort_input(&id, &input_id).await?,
        None => s.host.abort(&id).await?,
    }
    Ok((StatusCode::ACCEPTED, Json(json!({"abort_requested":true}))).into_response())
}

#[derive(Default, Deserialize)]
struct Cursor {
    after: Option<u64>,
}

async fn events(
    State(s): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(cursor): Query<Cursor>,
) -> Result<Response, HostError> {
    s.authority.authorize(&headers, &id, HostOperation::Read)?;
    let header_cursor = headers
        .get("last-event-id")
        .and_then(|h| h.to_str().ok())
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| HostError::Invalid("invalid Last-Event-ID".into()))?;
    let subscription = s
        .host
        .subscribe(&id, cursor.after.or(header_cursor).unwrap_or(0))?;
    let stream = futures_util::stream::unfold(
        (subscription, s.authority, headers, id),
        |(mut subscription, authority, headers, id)| async move {
            loop {
                if authority
                    .authorize(&headers, &id, HostOperation::Read)
                    .is_err()
                {
                    return None;
                }
                match tokio::time::timeout(Duration::from_secs(1), subscription.recv()).await {
                    Ok(Ok(event)) => {
                        if authority
                            .authorize(&headers, &id, HostOperation::Read)
                            .is_err()
                        {
                            return None;
                        }
                        let record = Event::default()
                            .event("agent")
                            .id(event.sequence.to_string())
                            .json_data(&event)
                            .ok()?;
                        return Some((
                            Ok::<_, Infallible>(record),
                            (subscription, authority, headers, id),
                        ));
                    }
                    Ok(Err(_)) => return None,
                    Err(_) => continue,
                }
            }
        },
    );
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}
