//! Client for speaking to another person's `<name>.proxy.ing` address over OAuth 2.1 + PKCE
//! and the `/client/v1/*` thread/agent routes.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::identity::encode_hex;

pub const AVATAR_TINTABLE_HEADER: &str = "x-proxy-avatar-tintable";
pub const MAX_AVATAR_BYTES: usize = 4 * 1024 * 1024;
const NO_SUCH_CLIENT: &str = "No client with that client_id has registered here";
const READ_AT_MOST: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("the address no longer admits this connection")]
    Unauthorized,
    #[error("{status} from the address: {body}")]
    Refused { status: u16, body: String },
    #[error("{0}")]
    Unreachable(String),
    #[error("{0}")]
    Transport(String),
}

fn edge_offline(status: u16) -> bool {
    matches!(status, 502..=504 | 520..=530)
}

impl ClientError {
    pub fn is_unreachable(&self) -> bool {
        match self {
            Self::Unreachable(_) => true,
            Self::Refused { status, .. } => edge_offline(*status),
            Self::Unauthorized | Self::Transport(_) => false,
        }
    }

    pub fn is_missing_route(&self) -> bool {
        matches!(self, Self::Refused { status: 404, .. })
    }

    pub fn is_refusal(&self) -> bool {
        match self {
            Self::Refused { status, .. } => {
                (400..500).contains(status) && !matches!(status, 408 | 429)
            }
            Self::Unauthorized => true,
            Self::Unreachable(_) | Self::Transport(_) => false,
        }
    }

    pub fn is_unknown_client(&self) -> bool {
        matches!(self, Self::Refused { status: 400, body } if body.contains(NO_SUCH_CLIENT))
    }

    pub fn plainly(&self) -> String {
        match self {
            Self::Refused { status, body } => match readable(body) {
                Some(said) => format!("the address answered {status}: {said}"),
                None => format!("the address answered {status}"),
            },
            other => other.to_string(),
        }
    }
}

fn readable(body: &str) -> Option<String> {
    let body = body
        .char_indices()
        .nth(READ_AT_MOST)
        .map_or(body, |(end, _)| &body[..end]);
    let body = body.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if body.is_empty() {
        return None;
    }
    let said = if body.starts_with('<') {
        page_words(body)?
    } else if let Ok(Value::Object(answer)) = serde_json::from_str::<Value>(body) {
        let said = ["error_description", "error", "message"]
            .iter()
            .find_map(|key| answer.get(*key).and_then(Value::as_str))?;
        one_line(said)
    } else {
        one_line(body)
    };
    (!said.is_empty()).then(|| said.chars().take(160).collect())
}

fn page_words(page: &str) -> Option<String> {
    let (heading, rest) = element_text(page, "h1").or_else(|| element_text(page, "title"))?;
    let message = element_text(rest, "p")
        .map(|(message, _)| message)
        .unwrap_or_default();
    let said = match (heading.is_empty(), message.is_empty()) {
        (_, true) => heading,
        (true, false) => message,
        (false, false) => format!("{}. {message}", heading.trim_end_matches('.')),
    };
    (!said.is_empty()).then_some(said)
}

fn element_text<'a>(html: &'a str, tag: &str) -> Option<(String, &'a str)> {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0;
    let inner = loop {
        let after = from + lower[from..].find(&open)? + open.len();
        if lower[after..].starts_with(|c: char| c == '>' || c.is_ascii_whitespace()) {
            break after + lower[after..].find('>')? + 1;
        }
        from = after;
    };
    let end = inner + lower[inner..].find(&close)?;
    Some((words(&html[inner..end]), &html[end + close.len()..]))
}

fn words(fragment: &str) -> String {
    let mut text = String::with_capacity(fragment.len());
    let mut in_tag = false;
    for c in fragment.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                text.push(' ');
            }
            _ if in_tag => {}
            _ => text.push(c),
        }
    }
    one_line(
        &text
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&"),
    )
}

fn one_line(text: &str) -> String {
    let kept: String = text
        .chars()
        .filter(|&c| !is_direction_mark(c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_direction_mark(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub ask_id: String,
    pub verifier: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskProgress {
    Waiting,
    LetIn(String),
    Refused,
    Gone,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Redirect {
    pub code: String,
    pub state: Option<String>,
    pub iss: Option<String>,
    pub client_id: Option<String>,
}

impl Redirect {
    pub fn parse(url: &str) -> Option<Self> {
        let query = url.split_once('?')?.1;
        let query = query.split('#').next().unwrap_or("");
        let mut redirect = Redirect::default();
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode_str(value).decode_utf8().ok()?.into_owned();
            match name {
                "code" => redirect.code = value,
                "state" => redirect.state = Some(value),
                "iss" => redirect.iss = Some(value),
                "client_id" => redirect.client_id = Some(value),
                _ => {}
            }
        }
        (!redirect.code.is_empty()).then_some(redirect)
    }
}

#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub access_token: String,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemoteItem {
    pub sequence_number: i64,
    #[serde(default)]
    pub role: Option<String>,
    pub item_type: String,
    #[serde(default)]
    pub content: Option<String>,
}

impl RemoteItem {
    pub fn is_assistant_message(&self) -> bool {
        self.role.as_deref() == Some("assistant") && self.item_type == "message"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avatar {
    pub bytes: Vec<u8>,
    pub extension: &'static str,
    pub tintable: bool,
}

pub fn is_loopback(base_url: &str) -> bool {
    let Some(rest) = base_url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(host, _)| host);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

pub fn base_url_is_allowed(base_url: &str, address: &str) -> bool {
    if base_url.contains(char::is_whitespace) || base_url.contains('#') {
        return false;
    }
    if base_url == format!("https://{address}.proxy.ing") {
        return true;
    }
    is_loopback(base_url) && !base_url.trim_start_matches("http://").contains('/')
}

fn http() -> Result<reqwest::Client, ClientError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|error| ClientError::Transport(error.to_string()))
}

fn request(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
) -> Result<reqwest::RequestBuilder, ClientError> {
    let base = base_url.trim_end_matches('/');
    let mut builder = http()?.request(method, format!("{base}{path}"));
    if is_loopback(base) {
        builder = builder.header("cf-connecting-ip", "127.0.0.1");
    }
    Ok(builder)
}

fn no_answer(error: reqwest::Error) -> ClientError {
    if error.is_builder() {
        ClientError::Transport(error.to_string())
    } else {
        ClientError::Unreachable(error.to_string())
    }
}

async fn send(builder: reqwest::RequestBuilder) -> Result<(u16, String), ClientError> {
    let response = builder.send().await.map_err(no_answer)?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(no_answer)?;
    Ok((status, body))
}

fn parse_json(body: &str) -> Result<Value, ClientError> {
    serde_json::from_str(body)
        .map_err(|error| ClientError::Transport(format!("unreadable answer: {error}")))
}

fn refused(status: u16, body: &str) -> ClientError {
    ClientError::Refused {
        status,
        body: body.chars().take(READ_AT_MOST).collect(),
    }
}

fn client_data(status: u16, body: &str) -> Result<Value, ClientError> {
    if status == 401 {
        return Err(ClientError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(refused(status, body));
    }
    let answer = parse_json(body)?;
    if answer.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(ClientError::Refused {
            status,
            body: answer
                .get("error")
                .map(Value::to_string)
                .unwrap_or_else(|| body.chars().take(READ_AT_MOST).collect()),
        });
    }
    Ok(answer.get("data").cloned().unwrap_or(Value::Null))
}

fn bearer(builder: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
    builder.header("authorization", format!("Bearer {token}"))
}

fn generate_pkce_pair() -> (String, String, String) {
    let mut verifier_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut verifier_bytes);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut state_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut state_bytes);
    let state = encode_hex(&state_bytes);
    (verifier, challenge, state)
}

pub async fn register(
    base_url: &str,
    client_name: &str,
    redirect_uri: &str,
) -> Result<String, ClientError> {
    let payload = json!({
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    let (status, body) = send(
        request(reqwest::Method::POST, base_url, "/oauth/register")?
            .header("accept", "application/json")
            .json(&payload),
    )
    .await?;
    if !(200..300).contains(&status) {
        return Err(refused(status, &body));
    }
    parse_json(&body)?
        .get("client_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|client_id| !client_id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ClientError::Transport("registration answered no client_id".into()))
}

pub async fn ask(
    base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
) -> Result<Asked, ClientError> {
    ask_signed(base_url, client_id, redirect_uri, scope, &|_| None).await
}

pub async fn ask_signed(
    base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    prove: &(dyn Fn(&str) -> Option<String> + Send + Sync),
) -> Result<Asked, ClientError> {
    let (verifier, challenge, state) = generate_pkce_pair();
    let final_scope = match prove(&challenge) {
        Some(word) => format!("{scope} {word}"),
        None => scope.to_string(),
    };
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let path = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        enc(client_id),
        enc(redirect_uri),
        enc(&final_scope),
        enc(&state),
        enc(&challenge),
    );
    let (status, body) =
        send(request(reqwest::Method::GET, base_url, &path)?.header("accept", "application/json"))
            .await?;
    if status != 200 {
        return Err(refused(status, &body));
    }
    let ask_id = parse_json(&body)?
        .get("ask")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ClientError::Transport("the authorize answer named no ask".into()))?;
    Ok(Asked {
        ask_id,
        verifier,
        state,
    })
}

pub async fn poll(base_url: &str, ask_id: &str) -> Result<AskProgress, ClientError> {
    let encoded = utf8_percent_encode(ask_id, NON_ALPHANUMERIC);
    let (status, body) = send(request(
        reqwest::Method::GET,
        base_url,
        &format!("/oauth/ask/{encoded}"),
    )?)
    .await?;
    if status == 404 {
        return Ok(AskProgress::Gone);
    }
    if status != 200 {
        return Err(refused(status, &body));
    }
    let answer = parse_json(&body)?;
    let redirect = answer
        .get("redirect")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(match answer.get("status").and_then(Value::as_str) {
        Some("waiting") => AskProgress::Waiting,
        Some("let_in") => AskProgress::LetIn(redirect),
        Some("refused") => AskProgress::Refused,
        Some("gone") => AskProgress::Gone,
        other => {
            return Err(ClientError::Transport(format!(
                "the ask answered an unknown status {other:?}"
            )));
        }
    })
}

pub async fn redeem(
    base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<IssuedToken, ClientError> {
    let body_form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        utf8_percent_encode(code, NON_ALPHANUMERIC),
        utf8_percent_encode(redirect_uri, NON_ALPHANUMERIC),
        utf8_percent_encode(client_id, NON_ALPHANUMERIC),
        utf8_percent_encode(verifier, NON_ALPHANUMERIC),
    );
    let (status, body) = send(
        request(reqwest::Method::POST, base_url, "/oauth/token")?
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_form),
    )
    .await?;
    if !(200..300).contains(&status) {
        return Err(refused(status, &body));
    }
    let answer = parse_json(&body)?;
    let access_token = answer
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ClientError::Transport("the token answer carried no bearer".into()))?;
    Ok(IssuedToken {
        access_token,
        scope: answer
            .get("scope")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

pub async fn revoke(base_url: &str, token: &str) -> Result<(), ClientError> {
    let body_form = format!("token={}", utf8_percent_encode(token, NON_ALPHANUMERIC));
    let (status, body) = send(
        request(reqwest::Method::POST, base_url, "/oauth/revoke")?
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_form),
    )
    .await?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(refused(status, &body))
    }
}

pub async fn create_thread(
    base_url: &str,
    token: &str,
    title: &str,
    party_title: &str,
    agent: &str,
    message: &str,
) -> Result<String, ClientError> {
    let (status, body) = send(bearer(
        request(reqwest::Method::POST, base_url, "/client/v1/threads")?.json(&json!({
            "title": title,
            "party_title": party_title,
            "kind": "direct",
            "participant": {"agent_id": agent},
            "message": message,
            "worksite": "none",
        })),
        token,
    ))
    .await?;
    client_data(status, &body)?
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ClientError::Transport("the new thread has no id".into()))
}

pub async fn send_message(
    base_url: &str,
    token: &str,
    thread_id: &str,
    content: &str,
    party_title: Option<&str>,
) -> Result<(), ClientError> {
    let mut payload = json!({"content": content});
    if let Some(title) = party_title {
        payload["party_title"] = json!(title);
    }
    let encoded = utf8_percent_encode(thread_id, NON_ALPHANUMERIC);
    let (status, body) = send(bearer(
        request(
            reqwest::Method::POST,
            base_url,
            &format!("/client/v1/threads/{encoded}/messages"),
        )?
        .json(&payload),
        token,
    ))
    .await?;
    client_data(status, &body).map(|_| ())
}

pub async fn queue_idle(base_url: &str, token: &str, thread_id: &str) -> Result<bool, ClientError> {
    let encoded = utf8_percent_encode(thread_id, NON_ALPHANUMERIC);
    let (status, body) = send(bearer(
        request(
            reqwest::Method::GET,
            base_url,
            &format!("/client/v1/threads/{encoded}/queue-idle"),
        )?,
        token,
    ))
    .await?;
    Ok(client_data(status, &body)?
        .get("idle")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

pub async fn messages_after(
    base_url: &str,
    token: &str,
    thread_id: &str,
    after: i64,
) -> Result<Vec<RemoteItem>, ClientError> {
    let encoded = utf8_percent_encode(thread_id, NON_ALPHANUMERIC);
    let (status, body) = send(bearer(
        request(
            reqwest::Method::GET,
            base_url,
            &format!("/client/v1/threads/{encoded}/messages?after={after}&limit=500"),
        )?,
        token,
    ))
    .await?;
    let data = client_data(status, &body)?;
    let items = data.get("items").cloned().unwrap_or_else(|| json!([]));
    serde_json::from_value(items)
        .map_err(|error| ClientError::Transport(format!("unreadable items: {error}")))
}

pub async fn agent_avatar(
    base_url: &str,
    token: &str,
    agent: &str,
) -> Result<Option<Avatar>, ClientError> {
    let encoded = utf8_percent_encode(agent, NON_ALPHANUMERIC);
    let response = bearer(
        request(
            reqwest::Method::GET,
            base_url,
            &format!("/client/v1/agents/{encoded}/avatar"),
        )?,
        token,
    )
    .send()
    .await
    .map_err(no_answer)?;
    let status = response.status().as_u16();
    if status == 401 {
        return Err(ClientError::Unauthorized);
    }
    if matches!(status, 403 | 404) {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        let body = response.text().await.unwrap_or_default();
        return Err(refused(status, &body));
    }
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_ascii_lowercase())
    };
    let extension = match header("content-type")
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    {
        Some("image/png") => "png",
        Some("image/jpeg") => "jpg",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        _ => return Ok(None),
    };
    let tintable = header(AVATAR_TINTABLE_HEADER).as_deref() == Some("true");
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AVATAR_BYTES as u64)
    {
        return Ok(None);
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(no_answer)? {
        if bytes.len() + chunk.len() > MAX_AVATAR_BYTES {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(Avatar {
        bytes,
        extension,
        tintable,
    }))
}
