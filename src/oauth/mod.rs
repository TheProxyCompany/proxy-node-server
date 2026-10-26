//! OAuth 2.1 authorization server for a Proxy's address (`https://<name>.proxy.ing`).
//!
//! Supports the authorization code grant with PKCE (S256, required), dynamic
//! client registration (RFC 7591), server metadata (RFC 8414),
//! protected-resource metadata (RFC 9728), revocation (RFC 7009), and issuer
//! identification on authorization responses (RFC 9207).
//!
//! Two seams are the node's to fill: [`Store`] keeps clients, asks, and tokens
//! ([`MemoryStore`] is the reference implementation), and [`Consent`] puts an
//! ask in front of the person and reports their answer. The HTTP routes live in
//! [`net`] under the `pull-http` feature.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::identity::encode_hex;

#[cfg(feature = "pull-http")]
pub mod net;
mod server;
mod store;

#[cfg(test)]
mod tests;

pub use server::{
    AuthorizeRequest, Issued, Progress, Refusal, Registered, Registration, RegistrationRefusal,
    ResourceMetadata, Server, ServerMetadata, TokenRefusal, TokenRequest, insufficient_scope,
    resource_metadata, server_metadata, www_authenticate,
};
pub use store::{Always, Consent, MemoryStore, Store};

/// An approved ask's code must be redeemed within this long.
pub const CODE_TTL_SECS: u64 = 10 * 60;
/// An ask nobody has answered stops waiting after this long.
pub const ASK_TTL_SECS: u64 = 15 * 60;
/// A token's `last_used_at` moves at most this often, so admitting a bearer
/// on every request is a read, not a write.
pub const TOUCH_EVERY_SECS: u64 = 60;
/// A token lasts this long from issue: thirty days.
pub const TOKEN_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// The `expires_at` of a purpose token ([`scope_is_purpose_only`]) that does
/// not run out on the clock.
pub const NO_EXPIRY: u64 = i64::MAX as u64;
/// One source may register this many clients in a window.
pub const REGISTER_LIMIT: (u32, u64) = (10, 10 * 60);
/// One source may open this many asks in a window.
pub const AUTHORIZE_LIMIT: (u32, u64) = (30, 10 * 60);

/// The path families a token can open at the address, each one word of a scope.
pub const FAMILIES: [&str; 8] = [
    "threads",
    "life-map-read",
    "life-map-write",
    "computer",
    "mail",
    "messages",
    "inference",
    "moves",
];
/// What an ask gets when it names no scope.
pub const DEFAULT_SCOPE: &str = "threads";

/// What a family opens, in plain words, for the ask the person sees.
pub fn family_words(family: &str) -> &'static str {
    match family {
        "threads" => "open threads with your agents and read and post in them",
        "life-map-read" => "read your Life Map",
        "life-map-write" => "change your Life Map, and use your Proxy's tools",
        "computer" => "control your computer and phone",
        "mail" => "read and send your mail",
        "messages" => "read and send your messages",
        "inference" => "run your models",
        "moves" => "see and resolve your Moves",
        _ => "",
    }
}

/// Normalize a requested scope into [`FAMILIES`] order followed by any purpose
/// scopes (`party:<id>;...`). Unknown scope tokens are rejected.
pub fn normalize_scope(requested: Option<&str>) -> Result<String, String> {
    let requested = requested.map(str::trim).unwrap_or("");
    if requested.is_empty() {
        return Ok(DEFAULT_SCOPE.to_string());
    }
    let mut families: Vec<&str> = Vec::new();
    let mut purposes: Vec<&str> = Vec::new();
    for word in requested.split_whitespace() {
        if FAMILIES.contains(&word) {
            if !families.contains(&word) {
                families.push(word);
            }
        } else if word.contains(':') && !word.starts_with(':') {
            if !purposes.contains(&word) {
                purposes.push(word);
            }
        } else {
            return Err(format!(
                "{word} is not a scope this address has; the scopes are {}",
                FAMILIES.join(", ")
            ));
        }
    }
    families.sort_by_key(|family| FAMILIES.iter().position(|known| known == family));
    Ok(families
        .into_iter()
        .chain(purposes)
        .collect::<Vec<_>>()
        .join(" "))
}

/// The families a stored scope names. A token with no scope opens
/// [`DEFAULT_SCOPE`] and nothing more.
pub fn scope_families(scope: Option<&str>) -> Vec<&'static str> {
    let scope = scope.map(str::trim).filter(|scope| !scope.is_empty());
    let words: Vec<&str> = match scope {
        Some(scope) => scope.split_whitespace().collect(),
        None => vec![DEFAULT_SCOPE],
    };
    FAMILIES
        .iter()
        .copied()
        .filter(|family| words.contains(family))
        .collect()
}

/// Whether a stored scope opens `family`.
pub fn scope_opens(scope: Option<&str>, family: &str) -> bool {
    scope_families(scope).contains(&family)
}

/// Whether a scope names a purpose (`party:<id>;...`) and no family.
pub fn scope_is_purpose_only(scope: &str) -> bool {
    let mut words = scope.split_whitespace().peekable();
    words.peek().is_some()
        && words
            .all(|word| !FAMILIES.contains(&word) && word.contains(':') && !word.starts_with(':'))
}

/// When a token issued at `now` for `scope` runs out.
pub fn expires_at_for(scope: &str, now: u64) -> u64 {
    if scope_is_purpose_only(scope) {
        NO_EXPIRY
    } else {
        now + TOKEN_TTL_SECS
    }
}

/// The origin a redirect sends the person back to: the host of an `https`
/// redirect, or `this machine` for loopback.
pub fn redirect_origin(redirect_uri: &str) -> String {
    let rest = redirect_uri
        .strip_prefix("https://")
        .or_else(|| redirect_uri.strip_prefix("http://"))
        .unwrap_or(redirect_uri);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(host, _)| host);
    if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        "this machine".to_string()
    } else {
        host.to_lowercase()
    }
}

/// Per-source sliding window rate limiter in memory.
pub struct Limiter {
    per: u32,
    window_secs: u64,
    pub(crate) windows: Mutex<HashMap<String, (u64, u32)>>,
}

impl Limiter {
    /// At most `per` events from one source in any `window_secs`.
    pub fn new(per: u32, window_secs: u64) -> Self {
        Self {
            per,
            window_secs,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Count one event from `source` at `now`: `true` if within the limit.
    pub fn allow(&self, source: &str, now: u64) -> bool {
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };
        if windows.len() >= 4096 {
            let window_secs = self.window_secs;
            windows.retain(|_, (started, _)| now.saturating_sub(*started) < window_secs);
        }
        let (started, count) = windows.entry(source.to_string()).or_insert((now, 0));
        if now.saturating_sub(*started) >= self.window_secs {
            *started = now;
            *count = 0;
        }
        if *count >= self.per {
            return false;
        }
        *count += 1;
        true
    }
}

/// Registered OAuth client metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub registered_at: u64,
}

/// One authorization request from `/oauth/authorize` until code redemption or
/// expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub issuer: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub asked_at: u64,
    pub code: Option<String>,
    pub code_issued_at: Option<u64>,
    pub code_used: bool,
}

/// Decision state for an [`Ask`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Pending,
    Approved,
    Denied,
}

/// Persisted bearer token record (stores SHA-256 hash, never raw secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub hash: String,
    pub scope: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub last_used_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl Token {
    pub fn is_live(&self) -> bool {
        self.revoked_at.is_none()
    }

    pub fn is_live_at(&self, now: u64) -> bool {
        self.is_live() && now < self.expires_at
    }

    pub fn runs_out(&self) -> bool {
        self.expires_at != NO_EXPIRY
    }

    pub fn families(&self) -> Vec<&'static str> {
        scope_families(self.scope.as_deref())
    }

    pub fn opens(&self, family: &str) -> bool {
        scope_opens(self.scope.as_deref(), family)
    }
}

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("store: {0}")]
    Store(String),
    #[error("consent: {0}")]
    Consent(String),
}

/// OAuth 2.1 §1.5 and RFC 8252 §7.3: `https`, or `http` on loopback, with no
/// fragment.
pub fn redirect_uri_is_allowed(uri: &str) -> bool {
    if uri.contains('#') || uri.contains(char::is_whitespace) {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        return rest.chars().next().is_some_and(|c| c != '/');
    }
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                host
            } else {
                authority
            }
        });
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// RFC 7636 §4.2: 43 to 128 characters of `[A-Za-z0-9-._~]`.
pub fn code_challenge_is_well_formed(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// RFC 7636 §4.6: `BASE64URL(SHA256(verifier)) == challenge`.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    if !code_challenge_is_well_formed(verifier) {
        return false;
    }
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    digest.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// Hex SHA-256 of the bearer string.
pub fn hash_token(bearer: &str) -> String {
    encode_hex(&Sha256::digest(bearer.as_bytes()))
}

/// `n` random bytes as lowercase hex.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

/// Append non-empty query parameters to `redirect_uri`.
pub fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let mut url = redirect_uri.to_string();
    let mut separator = if url.contains('?') { '&' } else { '?' };
    for (name, value) in params {
        if value.is_empty() {
            continue;
        }
        url.push(separator);
        url.push_str(name);
        url.push('=');
        url.extend(utf8_percent_encode(value, QUERY_VALUE));
        separator = '&';
    }
    url
}

const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
