//! PACT Identity / A2A 1.0 over the node's existing HTTP server.
//!
//! The application owns consent and issuer trust. It supplies a typed authority
//! and an explicit list of published agents. There is no anonymous execution,
//! command/path configuration, or automatic trust based on a JWT's key URL.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path as HttpPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use super::pact::{PactIdentity, checked_url};
use super::{AgentHost, AgentInput, HostError, valid_id};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PactPrincipal {
    pub issuer: String,
    pub subject: String,
}

/// Validate PA JWT identity and a current exact-agent consent grant. The
/// application must reject missing, revoked or unknown grants. A successfully
/// verified issuer signature alone is not permission to use a person's agent.
pub trait PactAuthority: Send + Sync + 'static {
    fn authorize(&self, headers: &HeaderMap, agent: &str) -> Result<PactPrincipal, HostError>;
}
impl<F> PactAuthority for F
where
    F: Fn(&HeaderMap, &str) -> Result<PactPrincipal, HostError> + Send + Sync + 'static,
{
    fn authorize(&self, headers: &HeaderMap, agent: &str) -> Result<PactPrincipal, HostError> {
        self(headers, agent)
    }
}

pub struct PublishedAgent {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Serialize, Deserialize)]
struct Context {
    principal: PactPrincipal,
    agent: String,
}

struct Server {
    host: AgentHost,
    identity: Arc<PactIdentity>,
    authority: Arc<dyn PactAuthority>,
    cards: HashMap<String, Value>,
    root: PathBuf,
    contexts: Mutex<HashMap<String, Arc<AsyncMutex<Context>>>>,
}

/// Mount this router on the existing node listener. `base_url` is its externally
/// reachable URL, not an inferred OAuth audience. Optional delegated authority
/// is not advertised: this endpoint uses the application's explicit grant.
pub fn router(
    host: AgentHost,
    identity: Arc<PactIdentity>,
    authority: Arc<dyn PactAuthority>,
    root: impl AsRef<Path>,
    base_url: &str,
    published: Vec<PublishedAgent>,
) -> Result<Router, HostError> {
    let base = checked_url(base_url)?
        .to_string()
        .trim_end_matches('/')
        .to_string();
    super::private_directory(root.as_ref())?;
    let mut cards = HashMap::new();
    for agent in published {
        if !valid_id(&agent.id) || !host.registered_agents().contains(&agent.id) {
            return Err(HostError::Invalid(
                "PACT publication requires a registered agent".into(),
            ));
        }
        cards.insert(agent.id.clone(),json!({"name":agent.name,"description":agent.description,"version":"1.0.0",
            "supportedInterfaces":[{"url":format!("{base}/a2a/{}",agent.id),"protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
            "capabilities":{"streaming":false,"pushNotifications":false,"extendedAgentCard":false},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],
            "skills":[{"id":"conversation","name":"Conversation","description":"Talk to this authorized persistent agent","tags":["conversation"]}],
            "securitySchemes":{"pact":{"httpAuthSecurityScheme":{"scheme":"Bearer","bearerFormat":"JWT"}}},
            "securityRequirements":[{"schemes":{"pact":{"list":[]}}}]}));
    }
    let state = Arc::new(Server {
        host,
        identity,
        authority,
        cards,
        root: root.as_ref().to_path_buf(),
        contexts: Mutex::new(HashMap::new()),
    });
    Ok(Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .route("/a2a/{agent}/.well-known/agent-card.json", get(card))
        .route("/a2a/{agent}/message:send", post(send))
        .route("/a2a/{agent}/tasks", get(tasks))
        .route("/a2a/{agent}/tasks/{task}", get(task).post(cancel_task))
        .with_state(state))
}

async fn jwks(State(state): State<Arc<Server>>) -> Json<Value> {
    Json(state.identity.jwks())
}
async fn card(State(state): State<Arc<Server>>, HttpPath(agent): HttpPath<String>) -> Response {
    match state.cards.get(&agent) {
        Some(card) => Json(card.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn failure(status: StatusCode, reason: &str, message: &str) -> Response {
    (status,[("content-type","application/a2a+json")],Json(json!({"error":{"code":status.as_u16(),"status":if status==StatusCode::BAD_REQUEST {"INVALID_ARGUMENT"} else if status==StatusCode::NOT_FOUND {"NOT_FOUND"} else {"INTERNAL"},"message":message,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":reason,"domain":"a2a-protocol.org"}]}}))).into_response()
}

fn digest(parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn save(root: &Path, id: &str, context: &impl Serialize) -> Result<(), HostError> {
    let temporary = root.join(format!("{id}.tmp"));
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(context)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, root.join(format!("{id}.json")))?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}

async fn send(
    State(state): State<Arc<Server>>,
    HttpPath(agent): HttpPath<String>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    if !state.cards.contains_key(&agent) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let principal = match state.authority.authorize(&headers, &agent) {
        Ok(principal) if !principal.issuer.is_empty() && !principal.subject.is_empty() => principal,
        _ => return unauthorized(),
    };
    if headers.get("a2a-version").and_then(|v| v.to_str().ok()) != Some("1.0") {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "A2A-Version must be 1.0",
        );
    }
    let bytes = match axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "INVALID_PARAMS",
                "Request body is too large or incomplete",
            );
        }
    };
    let body = match serde_json::from_slice::<Value>(&bytes) {
        Ok(body) => body,
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "INVALID_PARAMS",
                "Request must be valid JSON",
            );
        }
    };
    // A disconnected HTTP waiter does not cancel protocol reply persistence.
    tokio::spawn(execute(state, agent, headers, principal, body))
        .await
        .unwrap_or_else(|_| {
            failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Agent request failed",
            )
        })
}

async fn execute(
    state: Arc<Server>,
    agent: String,
    headers: HeaderMap,
    principal: PactPrincipal,
    body: Value,
) -> Response {
    let message = &body["message"];
    if message.get("taskId").is_some() {
        return failure(StatusCode::NOT_FOUND, "TASK_NOT_FOUND", "No such task");
    }
    let Some(id) = message["messageId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 256)
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "A bounded messageId is required",
        );
    };
    if message["role"] != "ROLE_USER" {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "The input role must be ROLE_USER",
        );
    }
    let Some(parts) = message["parts"]
        .as_array()
        .filter(|parts| !parts.is_empty() && parts.len() <= 1024)
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "Text parts are required",
        );
    };
    let mut texts = Vec::new();
    for part in parts {
        match part["text"].as_str() {
            Some(text) => texts.push(text),
            None => {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "CONTENT_TYPE_NOT_SUPPORTED",
                    "This agent accepts text parts",
                );
            }
        }
    }
    let text = texts.join("\n");
    if text.trim().is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "Text must not be blank",
        );
    }
    let context_id = match message.get("contextId") {
        Some(value) => match value
            .as_str()
            .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            Some(id) => id.to_string(),
            None => {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "INVALID_PARAMS",
                    "Invalid context or duplicate messageId without a stored reply",
                );
            }
        },
        None => digest(&[
            "pact-context",
            &principal.issuer,
            &principal.subject,
            &agent,
            id,
        ]),
    };
    let context = {
        let mut contexts = state.contexts.lock().unwrap();
        if let Some(context) = contexts.get(&context_id) {
            Arc::clone(context)
        } else {
            let path = state.root.join(format!("{context_id}.json"));
            let context = match std::fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<Context>(&bytes) {
                    Ok(context) => context,
                    Err(_) => {
                        return failure(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL",
                            "Stored context cannot be read",
                        );
                    }
                },
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && message.get("contextId").is_none() =>
                {
                    Context {
                        principal: principal.clone(),
                        agent: agent.clone(),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return failure(
                        StatusCode::BAD_REQUEST,
                        "INVALID_PARAMS",
                        "Invalid context or duplicate messageId without a stored reply",
                    );
                }
                Err(_) => {
                    return failure(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL",
                        "Stored context cannot be read",
                    );
                }
            };
            let context = Arc::new(AsyncMutex::new(context));
            contexts.insert(context_id.clone(), Arc::clone(&context));
            context
        }
    };
    let Ok(context) = context.try_lock() else {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "Invalid context or duplicate messageId without a stored reply",
        );
    };
    if context.principal != principal || context.agent != agent {
        return failure(
            StatusCode::BAD_REQUEST,
            "INVALID_PARAMS",
            "Invalid context or duplicate messageId without a stored reply",
        );
    }
    let reply_id = format!("{context_id}-{}", digest(&[id]));
    match std::fs::read(state.root.join(format!("{reply_id}.json"))) {
        Ok(bytes) => {
            return match serde_json::from_slice::<Value>(&bytes) {
                Ok(reply) => {
                    ([("content-type", "application/a2a+json")], Json(reply)).into_response()
                }
                Err(_) => failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL",
                    "Stored reply cannot be read",
                ),
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Stored reply cannot be read",
            );
        }
    }
    if save(&state.root, &context_id, &*context).is_err() {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Context could not be persisted",
        );
    }
    let input_id = digest(&["pact-message", &context_id, id]);
    // Replay from the durable host log also covers a disconnect or node restart
    // after execution settled but before the protocol reply was persisted.
    let sequence = state
        .host
        .status(&agent)
        .await
        .ok()
        .and_then(|status| status["sequence"].as_u64())
        .unwrap_or(0);
    let mut events = match state.host.subscribe(&agent, sequence) {
        Ok(events) => events,
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Agent is unavailable",
            );
        }
    };
    let input = AgentInput {
        id: input_id.clone(),
        kind: "prompt".into(),
        message: text,
        source: Some("pact-client".into()),
        conversation_id: Some(context_id.clone()),
        participant_id: Some(digest(&[&principal.issuer, &principal.subject])),
        task_id: Some(id.into()),
        data: Some(
            json!({"protocol":"PACT","version":"1.0","issuer":principal.issuer,"subject":principal.subject}),
        ),
    };
    let accepted = match state.host.submit(&agent, input).await {
        Ok(accepted) => accepted,
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "Acceptance is unknown; retry the same messageId and contextId",
            );
        }
    };
    if accepted["duplicate"] == true {
        events = match state.host.subscribe(&agent, 0) {
            Ok(events) => events,
            Err(_) => {
                return failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL",
                    "Agent replay is unavailable",
                );
            }
        };
    }
    let answer = tokio::time::timeout(Duration::from_secs(300), async {
        let mut text = String::new();
        loop {
            let event = events.recv().await?.event;
            if event["event_id"] != input_id {
                continue;
            }
            if event["type"] == "message_end"
                && event.pointer("/message/role").and_then(Value::as_str) == Some("assistant")
            {
                if let Some(parts) = event.pointer("/message/content").and_then(Value::as_array) {
                    text = parts
                        .iter()
                        .filter_map(|p| p["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                }
            }
            if event["type"] == "agent_settled" {
                if event["status"] != "done" || text.is_empty() {
                    return Err(HostError::Rejected(
                        "Runtime did not complete a text reply".into(),
                    ));
                }
                return Ok(text);
            }
        }
    })
    .await;
    let Ok(Ok(answer)) = answer else {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Reply is unavailable; retry the same messageId and contextId",
        );
    };
    // Recheck revocation before returning private output after a long turn.
    if state.authority.authorize(&headers, &agent).ok().as_ref() != Some(&principal) {
        return unauthorized();
    }
    let reply = json!({"message":{"messageId":format!("reply-{input_id}"),"contextId":context_id,"role":"ROLE_AGENT","parts":[{"text":answer}]}});
    if save(&state.root, &reply_id, &reply).is_err() {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Reply could not be persisted; retry the same messageId",
        );
    }
    ([("content-type", "application/a2a+json")], Json(reply)).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", "Bearer realm=\"a2a\"")],
    )
        .into_response()
}
fn authorize_operation(state: &Server, agent: &str, headers: &HeaderMap) -> Option<Response> {
    if !state.cards.contains_key(agent) {
        return Some(StatusCode::NOT_FOUND.into_response());
    }
    state
        .authority
        .authorize(headers, agent)
        .err()
        .map(|_| unauthorized())
}
async fn tasks(
    State(state): State<Arc<Server>>,
    HttpPath(agent): HttpPath<String>,
    request: Request,
) -> Response {
    if let Some(error) = authorize_operation(&state, &agent, request.headers()) {
        return error;
    }
    if let Some(query) = request.uri().query() {
        let parameters = reqwest::Url::parse(&format!("https://query.invalid/?{query}")).unwrap();
        for (key, value) in parameters.query_pairs() {
            if key == "pageSize"
                && value
                    .parse::<u8>()
                    .map_or(true, |n| !(1..=100).contains(&n))
            {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "INVALID_PARAMS",
                    "pageSize must be 1 through 100",
                );
            }
        }
    }
    (
        [("content-type", "application/a2a+json")],
        Json(json!({"tasks":[]})),
    )
        .into_response()
}
async fn task(
    State(state): State<Arc<Server>>,
    HttpPath((agent, _task)): HttpPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(error) = authorize_operation(&state, &agent, &headers) {
        return error;
    }
    failure(StatusCode::NOT_FOUND, "TASK_NOT_FOUND", "No such task")
}
async fn cancel_task(
    State(state): State<Arc<Server>>,
    HttpPath((agent, task)): HttpPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !task.ends_with(":cancel") {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if let Some(error) = authorize_operation(&state, &agent, &headers) {
        return error;
    }
    failure(StatusCode::NOT_FOUND, "TASK_NOT_FOUND", "No such task")
}
