//! Public `<name>.proxy.ing/<slug>` web page, agent/party cards, and `POST /<slug>`
//! body parser.

use axum::{
    Json,
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

pub use crate::profile::{
    ProfileConfig, PublicAgentItem, PublicPageItem, PublicPartyItem, PublicProfile, humanize_slug,
    profile_json_response, profile_page_response, read_profile_config,
};

const STYLE: &str = include_str!("address_web/page.css");
const AGENT_PAGE: &str = include_str!("address_web/agent.html");
const NOT_FOUND_PAGE: &str = include_str!("address_web/not_found.html");

pub const CONTACT_KINDS: &[&str] = &["seat", "web"];

#[derive(Debug, Default, Deserialize)]
pub struct SlugPostBody {
    #[serde(default, alias = "party_title")]
    pub title: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
}

pub fn parse_slug_post_body(body: &Bytes) -> (Option<String>, Option<String>, Option<String>) {
    if body.is_empty() {
        return (None, None, None);
    }
    if let Ok(parsed) = serde_json::from_slice::<SlugPostBody>(body) {
        let title = parsed
            .title
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let prompt = parsed
            .prompt
            .or(parsed.message)
            .or(parsed.content)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let device = parsed
            .device
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        return (title, prompt, device);
    }
    if let Ok(text) = std::str::from_utf8(body) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return (None, Some(trimmed.to_string()), None);
        }
    }
    (None, None, None)
}

pub fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn wants_json(headers: &HeaderMap) -> bool {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    accept.contains("application/json") && !accept.contains("text/html")
}

pub fn party_card_response(address: &str, id: &str, name: &str, memory: &str) -> Response {
    let body = json!({
        "address": address,
        "party": id,
        "name": name,
        "kind": "party",
        "memory": memory,
    });
    with_headers(StatusCode::OK, Json(body))
}

pub fn agent_card_response(address: &str, id: &str, name: &str) -> Response {
    let body = json!({
        "address": address,
        "agent": id,
        "name": name,
        "avatar": format!("/client/v1/agents/{id}/avatar"),
        "addressable": true,
        "kinds": CONTACT_KINDS,
    });
    with_headers(StatusCode::OK, Json(body))
}

pub fn not_found_json() -> Response {
    with_headers(StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" })))
}

pub fn not_found_html(address: &str) -> Response {
    html_response(StatusCode::NOT_FOUND, fill(NOT_FOUND_PAGE, address))
}

pub fn agent_page_response(address: &str, id: &str, name: &str) -> Response {
    let rendered = fill(AGENT_PAGE, address)
        .replace("{{agent_id}}", &escape_html(id))
        .replace("{{agent_name}}", &escape_html(name));
    html_response(StatusCode::OK, rendered)
}

fn fill(template: &str, address: &str) -> String {
    template
        .replace("{{style}}", STYLE)
        .replace("{{address}}", &escape_html(address))
}

pub fn html_response(status: StatusCode, body: String) -> Response {
    with_headers(status, Html(body))
}

pub fn with_headers(status: StatusCode, body: impl IntoResponse) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        body,
    )
        .into_response()
}

pub fn failed_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CACHE_CONTROL, "no-store")],
        "Something went wrong.",
    )
        .into_response()
}
