//! The OAuth routes (feature `pull-http`): [`router`] mounted under `/oauth`,
//! and [`well_known_router`] mounted under `/.well-known`.

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Serialize;

use super::{
    AuthorizeRequest, Consent, Progress, Refusal, Registered, Registration, Server, Store,
    TokenRequest, family_words, redirect_origin, resource_metadata, scope_families,
    server_metadata,
};

const SOURCE_HEADER: &str = "cf-connecting-ip";

/// Seconds since the epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Callback returning the node's own public address (`https://<name>.proxy.ing`
/// or `http://127.0.0.1:<port>`).
pub type Issuer = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Audit sink receiving registration and rate-limit events.
pub type Audit = Arc<dyn Fn(&str) + Send + Sync>;

/// A no-op [`Audit`] sink.
pub fn silent() -> Audit {
    Arc::new(|_| {})
}

struct At<S: Store, C: Consent> {
    server: Arc<Server<S, C>>,
    issuer: Issuer,
    audit: Audit,
}

impl<S: Store, C: Consent> Clone for At<S, C> {
    fn clone(&self) -> Self {
        Self {
            server: Arc::clone(&self.server),
            issuer: Arc::clone(&self.issuer),
            audit: Arc::clone(&self.audit),
        }
    }
}

/// `/register`, `/authorize`, `/ask/{id}`, `/token`, `/revoke`: mount under
/// `/oauth`.
pub fn router<S, C>(server: Arc<Server<S, C>>, issuer: Issuer, audit: Audit) -> Router
where
    S: Store + 'static,
    C: Consent + 'static,
{
    Router::new()
        .route("/register", post(register::<S, C>).options(preflight))
        .route("/authorize", get(authorize::<S, C>))
        .route("/ask/{id}", get(ask::<S, C>))
        .route("/token", post(token::<S, C>).options(preflight))
        .route("/revoke", post(revoke::<S, C>).options(preflight))
        .with_state(At {
            server,
            issuer,
            audit,
        })
}

fn source_of(headers: &HeaderMap) -> String {
    headers
        .get(SOURCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "this machine".to_string())
}

fn slowed(window_secs: u64, description: &str) -> Response {
    let mut response = json(
        StatusCode::TOO_MANY_REQUESTS,
        &serde_json::json!({ "error": "too_many_requests", "error_description": description }),
    );
    if let Ok(value) = window_secs.to_string().parse() {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// `/oauth-authorization-server` and `/oauth-protected-resource`: mount
/// under `/.well-known`.
pub fn well_known_router(issuer: Issuer) -> Router {
    Router::new()
        .route(
            "/oauth-authorization-server",
            get(authorization_server_metadata).options(preflight),
        )
        .route(
            "/oauth-protected-resource",
            get(protected_resource_metadata).options(preflight),
        )
        .route(
            "/oauth-protected-resource/{*rest}",
            get(protected_resource_metadata).options(preflight),
        )
        .with_state(issuer)
}

fn address(issuer: &Issuer) -> Result<String, Box<Response>> {
    issuer()
        .map(|issuer| issuer.trim_end_matches('/').to_string())
        .filter(|issuer| !issuer.is_empty())
        .ok_or_else(|| {
            Box::new(json(
                StatusCode::SERVICE_UNAVAILABLE,
                &serde_json::json!({ "error": "server_error", "error_description": "This node has no address yet." }),
            ))
        })
}

fn cors(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        "access-control-allow-origin",
        "*".parse().expect("static header"),
    );
    headers.insert(
        "access-control-allow-methods",
        "GET, POST, OPTIONS".parse().expect("static header"),
    );
    headers.insert(
        "access-control-allow-headers",
        "Content-Type, Authorization, MCP-Protocol-Version"
            .parse()
            .expect("static header"),
    );
    response
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    cors(
        (
            status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
    )
}

async fn preflight() -> Response {
    cors(StatusCode::NO_CONTENT.into_response())
}

async fn authorization_server_metadata(State(issuer): State<Issuer>) -> Response {
    match address(&issuer) {
        Ok(issuer) => json(StatusCode::OK, &server_metadata(&issuer)),
        Err(response) => *response,
    }
}

async fn protected_resource_metadata(State(issuer): State<Issuer>) -> Response {
    match address(&issuer) {
        Ok(issuer) => json(StatusCode::OK, &resource_metadata(&issuer)),
        Err(response) => *response,
    }
}

fn failed(error: super::OAuthError) -> Response {
    json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &serde_json::json!({ "error": "server_error", "error_description": error.to_string() }),
    )
}

async fn blocking<S, C, T>(
    server: Arc<Server<S, C>>,
    run: impl FnOnce(&Server<S, C>) -> T + Send + 'static,
) -> Result<T, Box<Response>>
where
    S: Store + 'static,
    C: Consent + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || run(&server))
        .await
        .map_err(|error| {
            Box::new(json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({ "error": "server_error", "error_description": error.to_string() }),
            ))
        })
}

async fn register<S, C>(
    State(At { server, audit, .. }): State<At<S, C>>,
    headers: HeaderMap,
    body: Result<axum::Json<Registration>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let source = source_of(&headers);
    let at = now();
    if !server.may_register(&source, at) {
        audit(&format!(
            "oauth: {source} was slowed: {} registrations in {} seconds",
            super::REGISTER_LIMIT.0,
            super::REGISTER_LIMIT.1
        ));
        return slowed(
            super::REGISTER_LIMIT.1,
            "Too many registrations from where you are; try again later.",
        );
    }
    let registration = match body {
        Ok(axum::Json(registration)) => registration,
        Err(rejection) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": "invalid_client_metadata", "error_description": rejection.body_text() }),
            );
        }
    };
    match blocking(server, move |server| server.register(registration, at)).await {
        Ok(Ok(Ok(client))) => {
            let origins: Vec<String> = client
                .redirect_uris
                .iter()
                .map(|uri| redirect_origin(uri))
                .collect();
            audit(&format!(
                "oauth: {source} registered {:?} ({}), sent back to {}",
                client.name,
                client.id,
                origins.join(", ")
            ));
            json(StatusCode::CREATED, &Registered::from(client))
        }
        Ok(Ok(Err(refusal))) => {
            audit(&format!(
                "oauth: {source} was refused a registration: {}",
                refusal.error_description
            ));
            json(StatusCode::BAD_REQUEST, &refusal)
        }
        Ok(Err(error)) => failed(error),
        Err(response) => *response,
    }
}

async fn authorize<S, C>(
    State(At {
        server,
        issuer,
        audit,
    }): State<At<S, C>>,
    headers: HeaderMap,
    Query(request): Query<AuthorizeRequest>,
) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let issuer = match address(&issuer) {
        Ok(issuer) => issuer,
        Err(response) => return *response,
    };
    let source = source_of(&headers);
    let at = now();
    if !server.may_ask(&source, at) {
        audit(&format!(
            "oauth: {source} was slowed: {} asks in {} seconds",
            super::AUTHORIZE_LIMIT.0,
            super::AUTHORIZE_LIMIT.1
        ));
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Html(page(
                &issuer,
                "Too many asks",
                "Too many asks to connect have come from where you are. Wait a few minutes and start again from where you were.",
                None,
            )),
        )
            .into_response();
        if let Ok(value) = super::AUTHORIZE_LIMIT.1.to_string().parse() {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    let wants_json = asks_for_json(&headers);
    let asked_at = issuer.clone();
    match blocking(server, move |server| {
        server.authorize(request, &asked_at, at)
    })
    .await
    {
        Ok(Ok(Ok(ask))) if wants_json => json(
            StatusCode::OK,
            &Asked {
                ask: ask.id.clone(),
                client_name: ask.client_name.clone(),
                origin: redirect_origin(&ask.redirect_uri),
                scope: ask.scope.clone().unwrap_or_default(),
                poll: format!("ask/{}", ask.id),
            },
        ),
        Ok(Ok(Ok(ask))) => waiting_page(&issuer, &ask),
        Ok(Ok(Err(Refusal::Redirect(url)))) => Redirect::to(&url).into_response(),
        Ok(Ok(Err(Refusal::Page { status, message }))) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
            (
                status,
                Html(page(&issuer, "This ask cannot go on", &message, None)),
            )
                .into_response()
        }
        Ok(Err(error)) => failed(error),
        Err(response) => *response,
    }
}

fn asks_for_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| {
            accept.split(',').any(|part| {
                part.trim().split(';').next().unwrap_or("").trim() == "application/json"
            })
        })
}

#[derive(Serialize)]
struct Asked {
    ask: String,
    client_name: String,
    origin: String,
    scope: String,
    poll: String,
}

#[derive(Serialize)]
struct AskProgress {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect: Option<String>,
}

async fn ask<S, C>(State(At { server, .. }): State<At<S, C>>, Path(id): Path<String>) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let at = now();
    match blocking(server, move |server| server.progress(&id, at)).await {
        Ok(Ok(Progress::Waiting)) => json(
            StatusCode::OK,
            &AskProgress {
                status: "waiting",
                redirect: None,
            },
        ),
        Ok(Ok(Progress::Redirect(url))) => json(
            StatusCode::OK,
            &AskProgress {
                status: "let_in",
                redirect: Some(url),
            },
        ),
        Ok(Ok(Progress::Denied(url))) => json(
            StatusCode::OK,
            &AskProgress {
                status: "refused",
                redirect: Some(url),
            },
        ),
        Ok(Ok(Progress::Gone)) => json(
            StatusCode::NOT_FOUND,
            &AskProgress {
                status: "gone",
                redirect: None,
            },
        ),
        Ok(Err(error)) => failed(error),
        Err(response) => *response,
    }
}

async fn token<S, C>(
    State(At { server, .. }): State<At<S, C>>,
    body: Result<Form<TokenRequest>, axum::extract::rejection::FormRejection>,
) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let request = match body {
        Ok(Form(request)) => request,
        Err(rejection) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": "invalid_request", "error_description": rejection.body_text() }),
            );
        }
    };
    let at = now();
    match blocking(server, move |server| server.token(request, at)).await {
        Ok(Ok(Ok(issued))) => json(StatusCode::OK, &issued),
        Ok(Ok(Err(refusal))) => json(
            StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::BAD_REQUEST),
            &refusal,
        ),
        Ok(Err(error)) => failed(error),
        Err(response) => *response,
    }
}

#[derive(serde::Deserialize)]
struct Revocation {
    token: Option<String>,
}

async fn revoke<S, C>(
    State(At { server, .. }): State<At<S, C>>,
    body: Result<Form<Revocation>, axum::extract::rejection::FormRejection>,
) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let Ok(Form(Revocation { token: Some(token) })) = body else {
        return json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": "invalid_request", "error_description": "token is required." }),
        );
    };
    let at = now();
    match blocking(server, move |server| server.revoke(&token, at)).await {
        Ok(Ok(())) => cors(StatusCode::OK.into_response()),
        Ok(Err(error)) => failed(error),
        Err(response) => *response,
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn address_of(issuer: &str) -> String {
    issuer
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

/// Human-readable description of what `scope` opens.
pub fn scope_words(scope: Option<&str>) -> String {
    let words: Vec<&str> = scope_families(scope)
        .into_iter()
        .map(family_words)
        .collect();
    match words.as_slice() {
        [] => "nothing at your address itself".to_string(),
        [one] => (*one).to_string(),
        [first @ .., last] => format!("{}, and {last}", first.join(", ")),
    }
}

fn waiting_page(issuer: &str, ask: &super::Ask) -> Response {
    let address = escape(&address_of(issuer));
    let client = escape(&ask.client_name);
    let origin = escape(&redirect_origin(&ask.redirect_uri));
    let asks_for = escape(&scope_words(ask.scope.as_deref()));
    let lede = format!(
        "<strong>{client}</strong> wants to connect to <strong>{address}</strong> and be \
         sent back to <strong>{origin}</strong>. It asks to {asks_for}, for thirty days. \
         Let it in from Proxy on your Mac or phone, or reject it there."
    );
    let html = page(
        issuer,
        "Let it in?",
        &lede,
        Some((ask.client_name.as_str(), ask.id.as_str())),
    );
    cors(
        (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Html(html),
        )
            .into_response(),
    )
}

const WAITING_SCRIPT: &str = r#"<script>
(function () {
  var note = document.getElementById("note");
  var client = note.dataset.client;
  var ask = new URL("ask/" + note.dataset.ask, location.href);
  var tick = function () {
    fetch(ask, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (answer) {
      if (answer.status === "let_in") {
        note.textContent = "Let in. Taking you back to " + client + "\u2026";
        location.replace(answer.redirect);
      } else if (answer.status === "refused") {
        note.textContent = "Not let in. Nothing changed. Taking you back\u2026";
        location.replace(answer.redirect);
      } else if (answer.status === "gone") {
        note.textContent = "This ask is no longer open. Start again from " + client + ".";
      } else {
        setTimeout(tick, 2000);
      }
    }).catch(function () { setTimeout(tick, 4000); });
  };
  tick();
})();
</script>"#;

fn page(issuer: &str, title: &str, lede_html: &str, waiting: Option<(&str, &str)>) -> String {
    let address = escape(&address_of(issuer));
    let title = escape(title);
    let (note, script) = match waiting {
        Some((client_name, ask_id)) => (
            format!(
                r#"<p id="note" class="note" data-client="{}" data-ask="{}">Waiting for you&hellip;</p>"#,
                escape(client_name),
                escape(ask_id)
            ),
            WAITING_SCRIPT,
        ),
        None => (
            r#"<p id="note" class="note">Go back to where you started and try again.</p>"#
                .to_string(),
            "",
        ),
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · {address}</title>
<style>
  :root {{ color-scheme: light dark; --ink: #18181b; --muted: #71717a; --paper: #fafafa; --line: #e4e4e7; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --ink: #fafafa; --muted: #a1a1aa; --paper: #09090b; --line: #27272a; }} }}
  body {{ margin: 0; background: var(--paper); color: var(--ink); font: 17px/1.5 -apple-system, BlinkMacSystemFont, "Inter", system-ui, sans-serif; }}
  main {{ max-width: 34rem; margin: 18vh auto 0; padding: 0 16px; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .75rem; }}
  p {{ margin: 0 0 1rem; }}
  .note {{ color: var(--muted); border-top: 1px solid var(--line); padding-top: 1rem; }}
  .address {{ color: var(--muted); font-size: .9rem; }}
</style>
</head>
<body>
<main>
  <p class="address">{address}</p>
  <h1>{title}</h1>
  <p>{lede}</p>
  {note}
</main>
{script}
</body>
</html>
"#,
        lede = lede_html,
    )
}
