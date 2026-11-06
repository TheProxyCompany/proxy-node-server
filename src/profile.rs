//! Open-source `.proxy.ing` Public Profile, `/p/home` root detection, and x402 Move price helpers.

use serde::{Deserialize, Serialize};

use crate::address::DOMAIN;
use crate::mail::format_proxy_ing_email;

pub const DEFAULT_WALLET_PROVIDER: &str = "Proxy <> Coinbase";
pub const DEFAULT_CUSTOM_HOME_URL: &str = "/p/home/";
pub const DEFAULT_MOVE_PRICE_CENTS: u64 = 10;

fn default_wallet_provider() -> String {
    DEFAULT_WALLET_PROVIDER.to_string()
}

fn default_custom_home_url() -> String {
    DEFAULT_CUSTOM_HOME_URL.to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicPageSummary {
    pub slug: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicAgentSummary {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    pub url: String,
    #[serde(default)]
    pub addressable: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicPartySummary {
    pub id: String,
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub participant_count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicProfilePayload {
    pub username: String,
    pub display_name: String,
    pub email_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub always_on: bool,
    pub move_price_usdc: String,
    pub move_price_cents: u64,
    #[serde(default = "default_wallet_provider")]
    pub wallet_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    #[serde(default)]
    pub has_custom_home: bool,
    #[serde(default = "default_custom_home_url")]
    pub custom_home_url: String,
    #[serde(default)]
    pub pages: Vec<PublicPageSummary>,
    #[serde(default)]
    pub agents: Vec<PublicAgentSummary>,
    #[serde(default)]
    pub parties: Vec<PublicPartySummary>,
}

/// Converts a handle like `"alex-smith"` or `"alex_smith"` into `"Alex Smith"`.
pub fn humanize_username(username: &str) -> String {
    let trimmed = username
        .trim()
        .trim_end_matches(&format!(".{DOMAIN}"))
        .trim();
    if trimmed.is_empty() {
        return "Proxy User".to_string();
    }
    let words: Vec<String> = trimmed
        .split(['-', '_', '.', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut word = String::with_capacity(part.len());
                    for c in first.to_uppercase() {
                        word.push(c);
                    }
                    word.push_str(&chars.as_str().to_ascii_lowercase());
                    word
                }
                None => String::new(),
            }
        })
        .collect();
    if words.is_empty() {
        trimmed.to_string()
    } else {
        words.join(" ")
    }
}

/// Formats a cent amount into a two-decimal USDC string (e.g. `10` -> `"0.10"`).
pub fn format_move_price_usdc(cents: u64) -> String {
    let dollars = cents / 100;
    let rem = cents % 100;
    format!("{dollars}.{rem:02}")
}

/// Builds the default `.proxy.ing` public profile payload for `username`.
pub fn default_public_profile(
    username: &str,
    online: bool,
    always_on: bool,
    has_custom_home: bool,
) -> PublicProfilePayload {
    let clean = username
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches(&format!(".{DOMAIN}"))
        .to_string();
    let display_name = humanize_username(&clean);
    let email_address = format_proxy_ing_email(&clean);
    let status = if online {
        if always_on {
            "Always-On Cloud Mirror".to_string()
        } else {
            "Online".to_string()
        }
    } else {
        "Offline".to_string()
    };
    PublicProfilePayload {
        username: clean,
        display_name: display_name.clone(),
        email_address,
        avatar_url: None,
        bio: format!("{display_name} on {DOMAIN}"),
        status,
        online,
        always_on,
        move_price_usdc: format_move_price_usdc(DEFAULT_MOVE_PRICE_CENTS),
        move_price_cents: DEFAULT_MOVE_PRICE_CENTS,
        wallet_provider: default_wallet_provider(),
        wallet_address: None,
        has_custom_home,
        custom_home_url: default_custom_home_url(),
        pages: Vec::new(),
        agents: Vec::new(),
        parties: Vec::new(),
    }
}

/// Injects `<base href="...">` into `<head>` so a `/p/home` bundle served at `/`
/// resolves relative assets against `/p/home/`.
pub fn inject_base_href(html: &str, base_href: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("<base ") || lower.contains("<base>") {
        return html.to_string();
    }
    let tag = format!("<base href=\"{base_href}\">");
    if let Some(head_idx) = lower.find("<head")
        && let Some(close_rel) = lower[head_idx..].find('>')
    {
        let insert_at = head_idx + close_rel + 1;
        let mut out = String::with_capacity(html.len() + tag.len());
        out.push_str(&html[..insert_at]);
        out.push_str(&tag);
        out.push_str(&html[insert_at..]);
        return out;
    }
    format!("{tag}{html}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanizes_usernames() {
        assert_eq!(humanize_username("alex"), "Alex");
        assert_eq!(humanize_username("alex-smith"), "Alex Smith");
        assert_eq!(humanize_username("the_mogul.proxy.ing"), "The Mogul");
        assert_eq!(humanize_username(""), "Proxy User");
    }

    #[test]
    fn formats_move_price_usdc_values() {
        assert_eq!(format_move_price_usdc(0), "0.00");
        assert_eq!(format_move_price_usdc(5), "0.05");
        assert_eq!(format_move_price_usdc(10), "0.10");
        assert_eq!(format_move_price_usdc(100), "1.00");
        assert_eq!(format_move_price_usdc(1250), "12.50");
    }

    #[test]
    fn builds_default_public_profile() {
        let profile = default_public_profile("alex-smith", true, true, true);
        assert_eq!(profile.username, "alex-smith");
        assert_eq!(profile.display_name, "Alex Smith");
        assert_eq!(profile.email_address, "alex-smith@proxy.ing");
        assert_eq!(profile.move_price_cents, 10);
        assert_eq!(profile.move_price_usdc, "0.10");
        assert_eq!(profile.wallet_provider, "Proxy <> Coinbase");
        assert!(profile.online);
        assert!(profile.always_on);
        assert!(profile.has_custom_home);
        assert_eq!(profile.custom_home_url, "/p/home/");
    }

    #[test]
    fn injects_base_href_into_head_once() {
        let raw = "<!doctype html><html><head><title>Home</title></head><body>Hi</body></html>";
        let injected = inject_base_href(raw, "/p/home/");
        assert_eq!(
            injected,
            "<!doctype html><html><head><base href=\"/p/home/\"><title>Home</title></head><body>Hi</body></html>"
        );
        assert_eq!(inject_base_href(&injected, "/p/home/"), injected);
    }

    #[test]
    fn injects_base_href_with_head_attributes_or_no_head() {
        let with_attrs = "<HTML><HEAD lang=\"en\"><meta charset=\"utf-8\"></HEAD></HTML>";
        assert_eq!(
            inject_base_href(with_attrs, "/p/home/"),
            "<HTML><HEAD lang=\"en\"><base href=\"/p/home/\"><meta charset=\"utf-8\"></HEAD></HTML>"
        );
        let headless = "<div>hello</div>";
        assert_eq!(
            inject_base_href(headless, "/p/home/"),
            "<base href=\"/p/home/\"><div>hello</div>"
        );
    }
}
