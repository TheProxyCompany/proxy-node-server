//! Open-source `.proxy.ing` Public Profile & Pages models and HTML renderer.
//!
//! Hosted in `proxy-node-server` so anyone can inspect the `.proxy.ing` profile
//! schema, `/p/<slug>` page cards, embedded `Proxy <> Coinbase` wallet badge,
//! and `<username>@proxy.ing` identity surface.

use std::path::Path;

use axum::{
    Json,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::address_web::escape_html;

const PROFILE_HTML: &str = include_str!("address_web/profile.html");

/// Optional author-controlled overrides at `<data_dir>/pages/profile.json`
/// or `<data_dir>/profile.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileConfig {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub move_price_usdc: Option<String>,
    #[serde(default)]
    pub move_price_cents: Option<u64>,
    #[serde(default)]
    pub wallet_address: Option<String>,
}

/// Published static page entry surfaced on `<username>.proxy.ing`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicPageItem {
    pub slug: String,
    pub title: String,
    pub description: String,
    pub url: String,
    pub canonical_url: String,
    pub published_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub og_image_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub is_home: bool,
}

/// Addressable agent seat exposed on `<username>.proxy.ing/<id>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAgentItem {
    pub id: String,
    pub name: String,
    pub role: String,
    pub description: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_url: Option<String>,
}

/// Standing multi-agent party surfaced on `<username>.proxy.ing`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicPartyItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub seats: usize,
    pub url: String,
}

/// Complete public profile payload served at `/p/_profile.json` and rendered
/// by [`profile_page_response`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicProfile {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
    pub bio: String,
    pub status: String,
    pub move_price_usdc: String,
    pub move_price_cents: u64,
    pub wallet_provider: String,
    #[serde(default)]
    pub wallet_address: Option<String>,
    pub email_address: String,
    pub has_custom_home: bool,
    pub custom_home_url: String,
    #[serde(default)]
    pub pages: Vec<PublicPageItem>,
    #[serde(default)]
    pub agents: Vec<PublicAgentItem>,
    #[serde(default)]
    pub parties: Vec<PublicPartyItem>,
}

impl PublicProfile {
    /// Construct a default `PublicProfile` for `username` when no custom pages
    /// or extra agents have been published yet.
    pub fn default_for(username: &str) -> Self {
        let clean = username.trim().to_ascii_lowercase();
        let username = if clean.is_empty() {
            "proxy".to_string()
        } else {
            clean
        };
        let display_name = humanize_slug(&username);
        let bio = format!(
            "Personal Proxy node, published pages, and standing parties for {display_name} on {username}.proxy.ing."
        );
        Self {
            email_address: format!("{username}@proxy.ing"),
            username: username.clone(),
            display_name: display_name.clone(),
            avatar_url: None,
            bio,
            status: "online".to_string(),
            move_price_usdc: "1.00".to_string(),
            move_price_cents: 100,
            wallet_provider: "Proxy <> Coinbase".to_string(),
            wallet_address: None,
            has_custom_home: false,
            custom_home_url: "/p/home/".to_string(),
            pages: Vec::new(),
            agents: vec![PublicAgentItem {
                id: "proxy".to_string(),
                name: "Proxy".to_string(),
                role: "Personal Proxy".to_string(),
                description: format!(
                    "Primary personal agent for {display_name} at {username}.proxy.ing — accepts Moves, OAuth connections, and direct turns."
                ),
                url: "/proxy".to_string(),
                avatar_url: None,
                accent_color: Some("#3DD2C6".to_string()),
                share_url: None,
            }],
            parties: Vec::new(),
        }
    }
}

/// Convert a slug or username (`"johnny-appleseed"`) into a title-cased display
/// name (`"Johnny Appleseed"`).
pub fn humanize_slug(slug: &str) -> String {
    let words: Vec<String> = slug
        .split(['-', '_', '.'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut word = first.to_uppercase().to_string();
                    word.push_str(chars.as_str());
                    word
                }
                None => String::new(),
            }
        })
        .collect();
    if words.is_empty() {
        "Proxy".to_string()
    } else {
        words.join(" ")
    }
}

/// Read the first valid `ProfileConfig` from `candidates`, falling back to
/// `ProfileConfig::default()`.
pub fn read_profile_config(candidates: &[&Path]) -> ProfileConfig {
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(cfg) = serde_json::from_slice::<ProfileConfig>(&bytes)
        {
            return cfg;
        }
    }
    ProfileConfig::default()
}

/// Return a `200 OK` JSON response for `profile`.
pub fn profile_json_response(profile: &PublicProfile) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "public, max-age=60"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(profile.clone()),
    )
        .into_response()
}

/// Render the open-source `.proxy.ing` HTML profile page for `profile`.
pub fn profile_page_response(profile: &PublicProfile) -> Response {
    let avatar_initial = profile
        .display_name
        .chars()
        .find(|c| c.is_alphanumeric())
        .unwrap_or('P')
        .to_uppercase()
        .to_string();

    let pages_html = if profile.pages.is_empty() {
        "<div class=\"item-card\"><p class=\"item-desc\">No public pages published yet. Publish any folder with <code>proxy page publish</code>.</p></div>".to_string()
    } else {
        profile
            .pages
            .iter()
            .map(|page| {
                let tag = if page.is_home { "home" } else { &page.slug };
                format!(
                    "<a class=\"item-card\" href=\"{url}\"><div class=\"item-head\"><span class=\"item-title\">{title}</span><span class=\"item-tag\">/p/{tag}</span></div><p class=\"item-desc\">{desc}</p></a>",
                    url = escape_html(&page.url),
                    title = escape_html(&page.title),
                    tag = escape_html(tag),
                    desc = escape_html(&page.description),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let mut seats_cards = Vec::new();
    for agent in &profile.agents {
        seats_cards.push(format!(
            "<a class=\"item-card\" href=\"{url}\"><div class=\"item-head\"><span class=\"item-title\">{name}</span><span class=\"item-tag\">{role}</span></div><p class=\"item-desc\">{desc}</p></a>",
            url = escape_html(&agent.url),
            name = escape_html(&agent.name),
            role = escape_html(&agent.role),
            desc = escape_html(&agent.description),
        ));
    }
    for party in &profile.parties {
        seats_cards.push(format!(
            "<a class=\"item-card\" href=\"{url}\"><div class=\"item-head\"><span class=\"item-title\">{name}</span><span class=\"item-tag\">{seats} seats</span></div><p class=\"item-desc\">{desc}</p></a>",
            url = escape_html(&party.url),
            name = escape_html(&party.name),
            seats = party.seats,
            desc = escape_html(&party.description),
        ));
    }
    let agents_html = if seats_cards.is_empty() {
        "<div class=\"item-card\"><p class=\"item-desc\">No public agents configured.</p></div>"
            .to_string()
    } else {
        seats_cards.join("\n")
    };

    let profile_json = serde_json::to_string(profile)
        .unwrap_or_else(|_| "{}".to_string())
        .replace("</", "<\\/");

    let rendered = PROFILE_HTML
        .replace("{{username}}", &escape_html(&profile.username))
        .replace("{{display_name}}", &escape_html(&profile.display_name))
        .replace("{{bio}}", &escape_html(&profile.bio))
        .replace("{{status}}", &escape_html(&profile.status))
        .replace("{{email_address}}", &escape_html(&profile.email_address))
        .replace(
            "{{wallet_provider}}",
            &escape_html(&profile.wallet_provider),
        )
        .replace(
            "{{move_price_usdc}}",
            &escape_html(&profile.move_price_usdc),
        )
        .replace("{{avatar_initial}}", &escape_html(&avatar_initial))
        .replace("{{pages_count}}", &profile.pages.len().to_string())
        .replace(
            "{{agents_count}}",
            &(profile.agents.len() + profile.parties.len()).to_string(),
        )
        .replace("{{pages_html}}", &pages_html)
        .replace("{{agents_html}}", &agents_html)
        .replace("{{profile_json}}", &profile_json);

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        Html(rendered),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn humanize_slug_formats_compound_names() {
        assert_eq!(humanize_slug("johnny-appleseed"), "Johnny Appleseed");
        assert_eq!(humanize_slug("eden_wq.ai"), "Eden Wq Ai");
        assert_eq!(humanize_slug(""), "Proxy");
    }

    #[test]
    fn read_profile_config_loads_first_matching_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.json");
        let valid = dir.path().join("profile.json");
        std::fs::write(
            &valid,
            r#"{"display_name":"Eden","bio":"Builder","move_price_usdc":"2.50","move_price_cents":250}"#,
        )
        .expect("write profile.json");

        let cfg = read_profile_config(&[missing.as_path(), valid.as_path()]);
        assert_eq!(cfg.display_name.as_deref(), Some("Eden"));
        assert_eq!(cfg.move_price_usdc.as_deref(), Some("2.50"));
        assert_eq!(cfg.move_price_cents, Some(250));
    }

    #[tokio::test]
    async fn profile_page_and_json_responses_render_expected_fields() {
        let mut profile = PublicProfile::default_for("eden");
        profile.pages.push(PublicPageItem {
            slug: "notes".to_string(),
            title: "Field Notes".to_string(),
            description: "Architecture notes".to_string(),
            url: "/p/notes/".to_string(),
            canonical_url: "https://eden.proxy.ing/p/notes/".to_string(),
            published_at: "2026-11-06T00:00:00Z".to_string(),
            updated_at: "2026-11-06T00:00:00Z".to_string(),
            og_image_url: None,
            icon_url: None,
            is_home: false,
        });

        let html_resp = profile_page_response(&profile);
        assert_eq!(html_resp.status(), StatusCode::OK);
        let html_bytes = to_bytes(html_resp.into_body(), usize::MAX)
            .await
            .expect("html bytes");
        let html = String::from_utf8(html_bytes.to_vec()).expect("utf8");
        assert!(html.contains("eden.proxy.ing"));
        assert!(html.contains("eden@proxy.ing"));
        assert!(html.contains("Proxy &lt;&gt; Coinbase"));
        assert!(html.contains("Field Notes"));
        assert!(html.contains("/v1/moves/inbound"));

        let json_resp = profile_json_response(&profile);
        assert_eq!(json_resp.status(), StatusCode::OK);
        let json_bytes = to_bytes(json_resp.into_body(), usize::MAX)
            .await
            .expect("json bytes");
        let decoded: PublicProfile = serde_json::from_slice(&json_bytes).expect("decode profile");
        assert_eq!(decoded, profile);
    }
}
