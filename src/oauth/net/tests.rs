use std::sync::{Arc, Mutex};

use axum::Router;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::{Digest, Sha256};

use super::*;
use crate::oauth::{Always, Answer, Ask, Consent, MemoryStore, OAuthError};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://jckwind.proxy.ing";

fn fixed_issuer(issuer: &str) -> Issuer {
    let issuer = issuer.to_string();
    Arc::new(move || Some(issuer.clone()))
}

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
        .nest(
            "/oauth",
            router(Arc::clone(&server), fixed_issuer(ISSUER), silent()),
        )
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

async fn register_as(client: &reqwest::Client, base: &str, name: &str, redirect: &str) -> String {
    let response = client
        .post(format!("{base}/oauth/register"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "client_name": name, "redirect_uris": [redirect] }).to_string())
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
    assert_eq!(answer["origin"], "official.proxy.ing");
    assert_eq!(answer["scope"], "party:p1");
    assert_eq!(answer["poll"], format!("ask/{ask_id}"));
    let text = client
        .get(format!("{base}/oauth/{}", answer["poll"].as_str().unwrap()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(value(&text)["status"], "waiting");
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
    assert_eq!(metadata["scopes_supported"][0], "threads");
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );

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

#[tokio::test]
async fn a_node_that_claims_its_address_after_it_started_answers_with_it_from_then_on() {
    let claimed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let issuer: Issuer = {
        let claimed = Arc::clone(&claimed);
        Arc::new(move || claimed.lock().unwrap().clone())
    };
    let server = Arc::new(Server::new(MemoryStore::new(), Always(Answer::Pending)));
    let app = Router::new()
        .nest("/oauth", router(server, Arc::clone(&issuer), silent()))
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
            "<strong>Claude</strong> wants to connect to <strong>jckwind.proxy.ing</strong> \
             and be sent back to <strong>this machine</strong>. It asks to open threads \
             with your agents and read and post in them, for thirty days."
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

    let text = client
        .get(format!("{base}/oauth/ask/{ask_id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(value(&text)["status"], "waiting");

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
    assert_eq!(issued["scope"], "threads");
    assert_eq!(issued["expires_in"], crate::oauth::TOKEN_TTL_SECS);
    let bearer = issued["access_token"].as_str().unwrap().to_string();
    assert!(server.admit(&bearer, now()).unwrap().is_some());

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

    let response = client
        .get(format!("{base}/oauth/ask/nothing"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn a_source_gets_its_share_of_registrations_and_asks_and_each_one_is_said() {
    let said: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let audit: Audit = {
        let said = Arc::clone(&said);
        Arc::new(move |line: &str| said.lock().unwrap().push(line.to_string()))
    };
    let server = Arc::new(Server::new(MemoryStore::new(), Always(Answer::Pending)));
    let app = Router::new().nest(
        "/oauth",
        router(Arc::clone(&server), fixed_issuer(ISSUER), audit),
    );
    let base = serve(app).await;
    let client = reqwest::Client::new();
    let redirect = "https://claude.ai/api/mcp/auth_callback";
    let register_from = |source: &'static str| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}/oauth/register"))
                .header("content-type", "application/json")
                .header("cf-connecting-ip", source)
                .body(
                    serde_json::json!({ "client_name": "Claude", "redirect_uris": [redirect] })
                        .to_string(),
                )
                .send()
                .await
                .unwrap()
        }
    };
    for _ in 0..crate::oauth::REGISTER_LIMIT.0 {
        assert_eq!(register_from("203.0.113.9").await.status(), 201);
    }
    let slowed = register_from("203.0.113.9").await;
    assert_eq!(slowed.status(), 429);
    assert_eq!(
        slowed.headers()["retry-after"],
        crate::oauth::REGISTER_LIMIT.1.to_string().as_str()
    );
    assert_eq!(
        value(&slowed.text().await.unwrap())["error"],
        "too_many_requests"
    );
    assert_eq!(register_from("203.0.113.10").await.status(), 201);
    {
        let said = said.lock().unwrap();
        let registered = said
            .iter()
            .filter(|line| line.contains("203.0.113.9 registered \"Claude\""))
            .count();
        assert_eq!(
            registered as u32,
            crate::oauth::REGISTER_LIMIT.0,
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|line| line.contains("sent back to claude.ai")),
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|line| line.contains("203.0.113.9 was slowed")),
            "{said:?}"
        );
    }

    let client_id = register(&client, &base, redirect).await;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let ask_from = |source: &'static str| {
        let client = client.clone();
        let base = base.clone();
        let client_id = client_id.clone();
        let challenge = challenge.clone();
        async move {
            client
                .get(format!(
                    "{base}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}",
                    utf8_percent_encode(redirect, NON_ALPHANUMERIC)
                ))
                .header("cf-connecting-ip", source)
                .send()
                .await
                .unwrap()
        }
    };
    for _ in 0..crate::oauth::AUTHORIZE_LIMIT.0 {
        assert_eq!(ask_from("198.51.100.7").await.status(), 200);
    }
    let slowed = ask_from("198.51.100.7").await;
    assert_eq!(slowed.status(), 429);
    assert!(slowed.headers().contains_key("retry-after"));
    assert!(slowed.text().await.unwrap().contains("Too many asks"));
    assert_eq!(ask_from("198.51.100.8").await.status(), 200);
}
