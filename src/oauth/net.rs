//! The OAuth routes (feature `pull-http`): what a client and the person's
//! browser reach at the address. Two routers, mounted by the node where its
//! address delivers them: [`router`] under `/oauth`, and
//! [`well_known_router`] under `/.well-known`. Both are given an [`Issuer`],
//! the node's own reading of its address, `https://<name>.proxy.ing`; no
//! request header says where the node is.
//!
//! Every answer here is public by design: registration, the waiting page,
//! the token exchange. What they guard is elsewhere, at the bearer gate on
//! the node's surfaces, which admits a token through
//! [`Server::admit`](super::Server::admit).

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
    TokenRequest, resource_metadata, server_metadata,
};

/// Seconds since the epoch, the clock the rules run on.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// How the node reads its own address, `https://<name>.proxy.ing`, or
/// `http://127.0.0.1:<port>` for a node reached directly. It is read when a
/// request needs it, because a Proxy claims its address while it runs;
/// `None` is a node with no address yet, and its routes say so.
pub type Issuer = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// The server behind the routes, and how it reads the address it answers at.
struct At<S: Store, C: Consent> {
    server: Arc<Server<S, C>>,
    issuer: Issuer,
}

impl<S: Store, C: Consent> Clone for At<S, C> {
    fn clone(&self) -> Self {
        Self {
            server: Arc::clone(&self.server),
            issuer: Arc::clone(&self.issuer),
        }
    }
}

/// `/register`, `/authorize`, `/ask/{id}`, `/token`, `/revoke`: mount under
/// `/oauth`.
pub fn router<S, C>(server: Arc<Server<S, C>>, issuer: Issuer) -> Router
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
        .with_state(At { server, issuer })
}

/// `/oauth-authorization-server` and `/oauth-protected-resource`: mount
/// under `/.well-known`. Both name the node's address.
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

/// The address as the routes use it, without a trailing slash, or the
/// answer for a node that has none yet, boxed so the Ok side stays small.
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

/// A store or consent failure is the node's, not the client's.
fn failed(error: super::OAuthError) -> Response {
    json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &serde_json::json!({ "error": "server_error", "error_description": error.to_string() }),
    )
}

/// Run a rule on the blocking pool: a store may be a database. The error is
/// the answer to send when the pool itself failed, boxed so the Ok side
/// stays small.
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
    State(At { server, .. }): State<At<S, C>>,
    body: Result<axum::Json<Registration>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let registration = match body {
        Ok(axum::Json(registration)) => registration,
        Err(rejection) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": "invalid_client_metadata", "error_description": rejection.body_text() }),
            );
        }
    };
    let at = now();
    match blocking(server, move |server| server.register(registration, at)).await {
        Ok(Ok(Ok(client))) => json(StatusCode::CREATED, &Registered::from(client)),
        Ok(Ok(Err(refusal))) => json(StatusCode::BAD_REQUEST, &refusal),
        Ok(Err(error)) => failed(error),
        Err(response) => *response,
    }
}

async fn authorize<S, C>(
    State(At { server, issuer }): State<At<S, C>>,
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
    let wants_json = asks_for_json(&headers);
    let asked_at = issuer.clone();
    let at = now();
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
                poll: format!("/oauth/ask/{}", ask.id),
            },
        ),
        Ok(Ok(Ok(ask))) => waiting_page(&issuer, &ask.client_name, &ask.id),
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

/// A client with no browser (a Proxy at another address seating this one
/// in a party) sends `Accept: application/json` and gets the ask to poll
/// instead of the waiting page.
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

/// The ask as a client polls it: what to poll and who the person is told
/// asked.
#[derive(Serialize)]
struct Asked {
    ask: String,
    client_name: String,
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

// --- The page the person sees ---

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

/// The waiting page: who wants in, where, and that the answer is given in
/// Proxy. It polls `ask/<id>` beside itself and follows the redirect that
/// comes back. The client's name and the ask's id ride on the note as data
/// attributes, escaped once for HTML, and the script reads them from there,
/// so the script itself carries nothing a client chose.
fn waiting_page(issuer: &str, client_name: &str, ask_id: &str) -> Response {
    let address = escape(&address_of(issuer));
    let client = escape(client_name);
    let lede = format!(
        "<strong>{client}</strong> wants to connect to <strong>{address}</strong>. \
         Let it in from Proxy on your Mac or phone, or reject it there."
    );
    let html = page(issuer, "Let it in?", &lede, Some((client_name, ask_id)));
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

/// The page, with a note that is either the ask still waiting (the client's
/// name and the ask's id, for [`WAITING_SCRIPT`]) or where to go from a
/// refusal.
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::oauth::{Always, Answer, Ask, Consent, MemoryStore, OAuthError};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    use sha2::{Digest, Sha256};

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const ISSUER: &str = "https://jckwind.proxy.ing";

    /// The address a test node has for as long as it runs.
    fn fixed_issuer(issuer: &str) -> Issuer {
        let issuer = issuer.to_string();
        Arc::new(move || Some(issuer.clone()))
    }

    /// A consent the test answers when it likes.
    struct Held(Mutex<Answer>);

    impl Consent for Held {
        fn ask(&self, _ask: &Ask) -> Result<(), OAuthError> {
            Ok(())
        }

        fn answer(&self, _ask: &Ask) -> Result<Answer, OAuthError> {
            Ok(*self.0.lock().unwrap())
        }
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn app<C: Consent + 'static>(consent: C) -> (Arc<Server<MemoryStore, C>>, Router) {
        let server = Arc::new(Server::new(MemoryStore::new(), consent));
        let app = Router::new()
            .nest("/oauth", router(Arc::clone(&server), fixed_issuer(ISSUER)))
            .nest("/.well-known", well_known_router(fixed_issuer(ISSUER)));
        (server, app)
    }

    fn value(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    fn redeem_body(code: &str, redirect: &str, client_id: &str) -> String {
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}&code_verifier={VERIFIER}",
            utf8_percent_encode(redirect, NON_ALPHANUMERIC)
        )
    }

    async fn register(client: &reqwest::Client, base: &str, redirect: &str) -> String {
        register_as(client, base, "Claude", redirect).await
    }

    async fn register_as(
        client: &reqwest::Client,
        base: &str,
        name: &str,
        redirect: &str,
    ) -> String {
        let response = client
            .post(format!("{base}/oauth/register"))
            .header("content-type", "application/json")
            .body(
                serde_json::json!({ "client_name": name, "redirect_uris": [redirect] }).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        value(&response.text().await.unwrap())["client_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// A client with no browser asks with `Accept: application/json` and
    /// gets the ask to poll instead of the page; the same ask then answers
    /// the poll like any other.
    #[tokio::test]
    async fn a_client_that_asks_for_json_gets_the_ask_to_poll_instead_of_the_page() {
        let (_, app) = app(Always(Answer::Pending));
        let base = serve(app).await;
        let client = reqwest::Client::new();
        let redirect = "https://official.proxy.ing/oauth/party-callback";
        let client_id = register(&client, &base, redirect).await;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        let response = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&state=s1&code_challenge={challenge}&code_challenge_method=S256&scope=party%3Ap1",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .header("accept", "application/json; q=0.9, text/html")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let answer = value(&response.text().await.unwrap());
        let ask_id = answer["ask"].as_str().unwrap().to_string();
        assert!(!ask_id.is_empty());
        assert_eq!(answer["client_name"], "Claude");
        assert_eq!(answer["poll"], format!("/oauth/ask/{ask_id}"));
        let text = client
            .get(format!("{base}{}", answer["poll"].as_str().unwrap()))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(value(&text)["status"], "waiting");
        // Without the header, and with an accept that is not JSON, the page.
        let page = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&state=s2&code_challenge={challenge}&code_challenge_method=S256",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .header("accept", "text/html,application/xhtml+xml")
            .send()
            .await
            .unwrap();
        assert!(
            page.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
    }

    /// The address is the node's own reading. A request that says otherwise
    /// in `Host` or `X-Forwarded-Host`, which any client can send, changes
    /// nothing: the metadata, the waiting page and the `iss` on the redirect
    /// all name the node's address.
    #[tokio::test]
    async fn the_address_is_the_nodes_whatever_the_headers_say() {
        let (_, app) = app(Always(Answer::Pending));
        let base = serve(app).await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let text = client
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .header("host", "evil.example")
            .header("x-forwarded-host", "evil.example")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let metadata = value(&text);
        assert_eq!(metadata["issuer"], ISSUER);
        assert_eq!(metadata["token_endpoint"], format!("{ISSUER}/oauth/token"));
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );

        // A path under the resource metadata answers the same.
        let text = client
            .get(format!(
                "{base}/.well-known/oauth-protected-resource/mcp/proxy"
            ))
            .header("x-forwarded-host", "evil.example")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let resource = value(&text);
        assert_eq!(resource["resource"], ISSUER);
        assert_eq!(resource["authorization_servers"][0], ISSUER);

        // The page and the refusal on the redirect name it too.
        let redirect = "https://claude.ai/api/mcp/auth_callback";
        let client_id = register(&client, &base, redirect).await;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        let html = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .header("x-forwarded-host", "evil.example")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains("wants to connect to <strong>jckwind.proxy.ing</strong>"),
            "{html}"
        );
        assert!(!html.contains("evil.example"), "{html}");
        let response = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .header("x-forwarded-host", "evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        let location = response.headers()["location"].to_str().unwrap();
        assert!(
            location.ends_with("&iss=https%3A%2F%2Fjckwind.proxy.ing"),
            "{location}"
        );

        let preflight = client
            .request(reqwest::Method::OPTIONS, format!("{base}/oauth/token"))
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), 204);
        assert_eq!(
            preflight.headers()["access-control-allow-methods"],
            "GET, POST, OPTIONS"
        );
    }

    /// A Proxy claims its address while it runs. Until then the routes say
    /// there is no address; from then on they answer with it, with no
    /// restart, because the address is read when a request needs it.
    #[tokio::test]
    async fn a_node_that_claims_its_address_after_it_started_answers_with_it_from_then_on() {
        let claimed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let issuer: Issuer = {
            let claimed = Arc::clone(&claimed);
            Arc::new(move || claimed.lock().unwrap().clone())
        };
        let server = Arc::new(Server::new(MemoryStore::new(), Always(Answer::Pending)));
        let app = Router::new()
            .nest("/oauth", router(server, Arc::clone(&issuer)))
            .nest("/.well-known", well_known_router(issuer));
        let base = serve(app).await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(
            value(&response.text().await.unwrap())["error_description"],
            "This node has no address yet."
        );

        *claimed.lock().unwrap() = Some("https://jckwind.proxy.ing/".to_string());
        let text = client
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(value(&text)["issuer"], ISSUER);
        let redirect = "https://claude.ai/api/mcp/auth_callback";
        let client_id = register(&client, &base, redirect).await;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        let html = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains("wants to connect to <strong>jckwind.proxy.ing</strong>"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn a_client_registers_the_person_lets_it_in_and_it_redeems_the_code() {
        let held = Held(Mutex::new(Answer::Pending));
        let (server, app) = app(held);
        let base = serve(app).await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let redirect = "http://localhost:4242/callback";
        let client_id = register(&client, &base, redirect).await;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));

        // The waiting page, with the ask id in its script.
        let response = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&state=s1&code_challenge={challenge}&code_challenge_method=S256",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let html = response.text().await.unwrap();
        assert!(
            html.contains(
                "<strong>Claude</strong> wants to connect to <strong>jckwind.proxy.ing</strong>"
            ),
            "{html}"
        );
        let ask_id = html
            .split("data-ask=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string();

        // Nobody has answered.
        let text = client
            .get(format!("{base}/oauth/ask/{ask_id}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(value(&text)["status"], "waiting");

        // The person lets it in: the page is told where to go.
        *server.consent().0.lock().unwrap() = Answer::Approved;
        let text = client
            .get(format!("{base}/oauth/ask/{ask_id}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let answer = value(&text);
        assert_eq!(answer["status"], "let_in");
        let url = answer["redirect"].as_str().unwrap();
        assert!(
            url.starts_with("http://localhost:4242/callback?code="),
            "{url}"
        );
        assert!(
            url.contains(&format!(
                "&state=s1&iss=https%3A%2F%2Fjckwind.proxy.ing&client_id={client_id}"
            )),
            "{url}"
        );
        let code = url
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // The client redeems the code with its verifier and gets a bearer.
        let response = client
            .post(format!("{base}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(redeem_body(code, redirect, &client_id))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let issued = value(&response.text().await.unwrap());
        assert_eq!(issued["token_type"], "Bearer");
        let bearer = issued["access_token"].as_str().unwrap().to_string();
        assert!(server.admit(&bearer, now()).unwrap().is_some());

        // A second redemption is refused as a client would expect.
        let response = client
            .post(format!("{base}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(redeem_body(code, redirect, &client_id))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            value(&response.text().await.unwrap())["error"],
            "invalid_grant"
        );

        // Revoked from the client's side, the bearer is out.
        let response = client
            .post(format!("{base}/oauth/revoke"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("token={bearer}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(server.admit(&bearer, now()).unwrap().is_none());
    }

    /// A client's name is escaped once for each place it is shown. On the
    /// page it is HTML; the script reads it from a data attribute, so a
    /// name with a quote, an ampersand or a tag reads as the person expects
    /// and runs nothing.
    #[tokio::test]
    async fn a_clients_name_is_escaped_once_for_the_page_and_once_for_the_script() {
        let (_, app) = app(Always(Answer::Pending));
        let base = serve(app).await;
        let client = reqwest::Client::new();
        let redirect = "http://localhost:4242/callback";
        let client_id = register_as(&client, &base, "Jack's Editor & Co <b>", redirect).await;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        let html = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains("<strong>Jack&#39;s Editor &amp; Co &lt;b&gt;</strong> wants to connect"),
            "{html}"
        );
        assert!(
            html.contains(r#"data-client="Jack&#39;s Editor &amp; Co &lt;b&gt;" data-ask=""#),
            "{html}"
        );
        assert!(html.contains("note.dataset.client"), "{html}");
        let script = html.split("<script>").nth(1).unwrap();
        assert!(!script.contains("Jack"), "{script}");
        assert!(!html.contains("<b>"), "{html}");
    }

    #[tokio::test]
    async fn a_refusal_the_client_can_hear_is_a_redirect_and_one_it_cannot_is_a_page() {
        let (_, app) = app(Always(Answer::Pending));
        let base = serve(app).await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let redirect = "https://claude.ai/api/mcp/auth_callback";
        let client_id = register(&client, &base, redirect).await;

        // Known client, no PKCE: back to the client with the error.
        let response = client
            .get(format!(
                "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&state=s1",
                utf8_percent_encode(redirect, NON_ALPHANUMERIC)
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        let location = response.headers()["location"].to_str().unwrap();
        assert!(
            location.starts_with("https://claude.ai/api/mcp/auth_callback?error=invalid_request&"),
            "{location}"
        );

        // A redirect nobody registered: a page, never a redirect.
        let response = client
            .get(format!("{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fevil.example%2F"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("not one the client registered")
        );

        // A registration with nowhere allowed to go back to.
        let response = client
            .post(format!("{base}/oauth/register"))
            .header("content-type", "application/json")
            .body(r#"{"client_name":"X","redirect_uris":["http://evil.example/cb"]}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            value(&response.text().await.unwrap())["error"],
            "invalid_redirect_uri"
        );

        // An ask nobody made.
        let response = client
            .get(format!("{base}/oauth/ask/nothing"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
}
