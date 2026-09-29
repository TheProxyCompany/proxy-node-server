//! The OAuth routes (feature `pull-http`): what a client and the person's
//! browser reach at the address. Two routers, mounted by the node where its
//! address delivers them: [`router`] under `/oauth`, and
//! [`well_known_router`] under `/.well-known`.
//!
//! Every answer here is public by design: registration, the waiting page,
//! the token exchange. What they guard is elsewhere — the bearer gate on the
//! node's surfaces, which admits a token through
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

/// The issuer a request was made to: `https://<host>`, or `http://` when the
/// host is the loopback (a node reached directly, in development or tests).
/// The address is what the tunnel preserves in `Host`.
pub fn issuer_of(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .unwrap_or("localhost");
    let bare = host.rsplit_once(':').map_or(host, |(name, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            name
        } else {
            host
        }
    });
    let scheme = if matches!(bare, "localhost" | "127.0.0.1" | "[::1]") {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{host}")
}

/// `/register`, `/authorize`, `/ask/{id}`, `/token`, `/revoke`: mount under
/// `/oauth`.
pub fn router<S, C>(server: Arc<Server<S, C>>) -> Router
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
        .with_state(server)
}

/// `/oauth-authorization-server` and `/oauth-protected-resource`: mount
/// under `/.well-known`. Both are built from the host the request came to.
pub fn well_known_router() -> Router {
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

async fn authorization_server_metadata(headers: HeaderMap) -> Response {
    json(StatusCode::OK, &server_metadata(&issuer_of(&headers)))
}

async fn protected_resource_metadata(headers: HeaderMap) -> Response {
    json(StatusCode::OK, &resource_metadata(&issuer_of(&headers)))
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
    State(server): State<Arc<Server<S, C>>>,
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
    State(server): State<Arc<Server<S, C>>>,
    headers: HeaderMap,
    Query(request): Query<AuthorizeRequest>,
) -> Response
where
    S: Store + 'static,
    C: Consent + 'static,
{
    let issuer = issuer_of(&headers);
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

async fn ask<S, C>(State(server): State<Arc<Server<S, C>>>, Path(id): Path<String>) -> Response
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
    State(server): State<Arc<Server<S, C>>>,
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
    State(server): State<Arc<Server<S, C>>>,
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
/// comes back.
fn waiting_page(issuer: &str, client_name: &str, ask_id: &str) -> Response {
    let address = escape(&address_of(issuer));
    let client = escape(client_name);
    let lede = format!(
        "<strong>{client}</strong> wants to connect to <strong>{address}</strong>. \
         Let it in from Proxy on your Mac or phone, or reject it there."
    );
    let script = format!(
        r#"<script>
(function () {{
  var ask = new URL("ask/{id}", location.href);
  var note = document.getElementById("note");
  var tick = function () {{
    fetch(ask, {{ cache: "no-store" }}).then(function (r) {{ return r.json(); }}).then(function (answer) {{
      if (answer.status === "let_in") {{
        note.textContent = "Let in. Taking you back to {client_js}…";
        location.replace(answer.redirect);
      }} else if (answer.status === "refused") {{
        note.textContent = "Not let in. Nothing changed. Taking you back…";
        location.replace(answer.redirect);
      }} else if (answer.status === "gone") {{
        note.textContent = "This ask is no longer open. Start again from {client_js}.";
      }} else {{
        setTimeout(tick, 2000);
      }}
    }}).catch(function () {{ setTimeout(tick, 4000); }});
  }};
  tick();
}})();
</script>"#,
        id = escape(ask_id),
        client_js = client.replace('\\', "\\\\").replace('"', "\\\""),
    );
    let html = page(issuer, "Let it in?", &lede, Some(&script));
    cors(
        (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Html(html),
        )
            .into_response(),
    )
}

fn page(issuer: &str, title: &str, lede_html: &str, script: Option<&str>) -> String {
    let address = escape(&address_of(issuer));
    let title = escape(title);
    let note = if script.is_some() {
        "Waiting for you\u{2026}"
    } else {
        "Go back to where you started and try again."
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
  <p id="note" class="note">{note}</p>
</main>
{script}
</body>
</html>
"#,
        lede = lede_html,
        script = script.unwrap_or(""),
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
            .nest("/oauth", router(Arc::clone(&server)))
            .nest("/.well-known", well_known_router());
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
        let response = client
            .post(format!("{base}/oauth/register"))
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"client_name":"Claude","redirect_uris":["{redirect}"]}}"#
            ))
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
            .header("host", "jckwind.proxy.ing")
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

    #[tokio::test]
    async fn the_metadata_names_the_host_the_request_came_to() {
        let (_, app) = app(Always(Answer::Pending));
        let base = serve(app).await;
        let client = reqwest::Client::new();
        let text = client
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .header("host", "jckwind.proxy.ing")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let metadata = value(&text);
        assert_eq!(metadata["issuer"], "https://jckwind.proxy.ing");
        assert_eq!(
            metadata["token_endpoint"],
            "https://jckwind.proxy.ing/oauth/token"
        );
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );

        // Reached on the loopback, it is http; a path under the resource
        // metadata answers the same.
        let text = client
            .get(format!(
                "{base}/.well-known/oauth-protected-resource/mcp/proxy"
            ))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let resource = value(&text);
        assert_eq!(resource["resource"], base);
        assert_eq!(resource["authorization_servers"][0], base);

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
            .header("host", "jckwind.proxy.ing")
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
            .split("new URL(\"ask/")
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
