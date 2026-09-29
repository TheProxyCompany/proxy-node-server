//! OAuth for a Proxy's address.
//!
//! The node is the authorization server for the surfaces it serves at
//! `https://<name>.proxy.ing` — `/mcp`, `/inference`, `/client`. Something
//! that wants in (Claude, an editor, a dashboard) registers itself, sends the
//! person to `/oauth/authorize`, and the person lets it in from Proxy on
//! their Mac or phone: one click, nothing to paste. The node then issues the
//! token the client carries as its bearer, and the person takes it back
//! whenever they like.
//!
//! This is OAuth 2.1 as MCP clients speak it: the authorization code grant
//! with PKCE (S256, required), dynamic client registration (RFC 7591), server
//! metadata (RFC 8414), protected-resource metadata (RFC 9728), revocation
//! (RFC 7009), and the issuer named on every answer to an authorize
//! (RFC 9207), so a client that was sent here by a deep link into Proxy
//! learns which address let it in. Clients are public — there is no client secret — because
//! holding the code verifier is the proof.
//!
//! Two seams are the node's to fill. A [`Store`] keeps clients, asks and
//! tokens; [`MemoryStore`] is the reference. A [`Consent`] puts an ask in
//! front of the person and reports what they said. The HTTP routes are in
//! [`net`], under the `pull-http` feature.

use std::collections::HashMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "pull-http")]
pub mod net;

/// An approved ask's code must be redeemed within this long.
pub const CODE_TTL_SECS: u64 = 10 * 60;
/// An ask nobody has answered stops waiting after this long.
pub const ASK_TTL_SECS: u64 = 15 * 60;
/// A token's `last_used_at` moves at most this often, so admitting a bearer
/// on every request is a read, not a write.
pub const TOUCH_EVERY_SECS: u64 = 60;

/// Something registered to connect: what it calls itself, and where it may be
/// sent back to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub registered_at: u64,
}

/// One request to connect, from the moment a client sends the person to
/// `/oauth/authorize` until its code is redeemed or it goes stale.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    /// The address that was asked, `https://<name>.proxy.ing`: named as
    /// `iss` on the answer, with the client's id, so a client sent here by
    /// Proxy itself learns where to redeem its code.
    pub issuer: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub asked_at: u64,
    /// Minted the moment the person lets the client in.
    pub code: Option<String>,
    pub code_issued_at: Option<u64>,
    pub code_used: bool,
}

/// What the person has said about an ask so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Pending,
    Approved,
    Denied,
}

/// A token a client holds. Only its hash is kept; the token itself is shown
/// once, at issue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub hash: String,
    pub scope: Option<String>,
    pub issued_at: u64,
    pub last_used_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl Token {
    pub fn is_live(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("store: {0}")]
    Store(String),
    #[error("consent: {0}")]
    Consent(String),
}

/// Where clients, asks and tokens are kept. `put_client` and `put_ask` are
/// upserts by id. A token is different, because taking one back must be
/// final: `put_token` inserts a token, or on an id it already holds records
/// its revocation, and a `revoked_at` once set is never cleared by a later
/// put. `last_used_at` moves only through `touch_token`, which writes that
/// one column of a live token and nothing else, so a request admitted just
/// before the person removed the connection cannot write the old row back
/// and restore it.
pub trait Store: Send + Sync {
    fn put_client(&self, client: &Client) -> Result<(), OAuthError>;
    fn client(&self, id: &str) -> Result<Option<Client>, OAuthError>;
    fn put_ask(&self, ask: &Ask) -> Result<(), OAuthError>;
    fn ask(&self, id: &str) -> Result<Option<Ask>, OAuthError>;
    fn ask_by_code(&self, code: &str) -> Result<Option<Ask>, OAuthError>;
    fn put_token(&self, token: &Token) -> Result<(), OAuthError>;
    /// Record that the live token `id` was used at `used_at`. A token that
    /// is revoked, or that does not exist, is left exactly as it is.
    fn touch_token(&self, id: &str, used_at: u64) -> Result<(), OAuthError>;
    fn token(&self, id: &str) -> Result<Option<Token>, OAuthError>;
    fn token_by_hash(&self, hash: &str) -> Result<Option<Token>, OAuthError>;
    fn tokens(&self) -> Result<Vec<Token>, OAuthError>;
}

/// How an ask reaches the person, and how their answer comes back. On a
/// Proxy this is a Move — "Claude wants to connect to your address" — on the
/// Mac and the phone; `answer` reads that Move's status.
pub trait Consent: Send + Sync {
    fn ask(&self, ask: &Ask) -> Result<(), OAuthError>;
    fn answer(&self, ask: &Ask) -> Result<Answer, OAuthError>;
}

/// The reference store: everything in memory, gone with the process.
#[derive(Default)]
pub struct MemoryStore {
    clients: Mutex<HashMap<String, Client>>,
    asks: Mutex<HashMap<String, Ask>>,
    tokens: Mutex<HashMap<String, Token>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> OAuthError {
    OAuthError::Store("memory store lock poisoned".to_string())
}

impl Store for MemoryStore {
    fn put_client(&self, client: &Client) -> Result<(), OAuthError> {
        self.clients
            .lock()
            .map_err(poisoned)?
            .insert(client.id.clone(), client.clone());
        Ok(())
    }

    fn client(&self, id: &str) -> Result<Option<Client>, OAuthError> {
        Ok(self.clients.lock().map_err(poisoned)?.get(id).cloned())
    }

    fn put_ask(&self, ask: &Ask) -> Result<(), OAuthError> {
        self.asks
            .lock()
            .map_err(poisoned)?
            .insert(ask.id.clone(), ask.clone());
        Ok(())
    }

    fn ask(&self, id: &str) -> Result<Option<Ask>, OAuthError> {
        Ok(self.asks.lock().map_err(poisoned)?.get(id).cloned())
    }

    fn ask_by_code(&self, code: &str) -> Result<Option<Ask>, OAuthError> {
        Ok(self
            .asks
            .lock()
            .map_err(poisoned)?
            .values()
            .find(|ask| ask.code.as_deref() == Some(code))
            .cloned())
    }

    fn put_token(&self, token: &Token) -> Result<(), OAuthError> {
        let mut tokens = self.tokens.lock().map_err(poisoned)?;
        match tokens.get_mut(&token.id) {
            Some(held) => {
                if held.revoked_at.is_none() {
                    held.revoked_at = token.revoked_at;
                }
            }
            None => {
                tokens.insert(token.id.clone(), token.clone());
            }
        }
        Ok(())
    }

    fn touch_token(&self, id: &str, used_at: u64) -> Result<(), OAuthError> {
        if let Some(held) = self.tokens.lock().map_err(poisoned)?.get_mut(id) {
            if held.is_live() {
                held.last_used_at = Some(used_at);
            }
        }
        Ok(())
    }

    fn token(&self, id: &str) -> Result<Option<Token>, OAuthError> {
        Ok(self.tokens.lock().map_err(poisoned)?.get(id).cloned())
    }

    fn token_by_hash(&self, hash: &str) -> Result<Option<Token>, OAuthError> {
        Ok(self
            .tokens
            .lock()
            .map_err(poisoned)?
            .values()
            .find(|token| token.hash == hash)
            .cloned())
    }

    fn tokens(&self) -> Result<Vec<Token>, OAuthError> {
        let mut tokens: Vec<Token> = self
            .tokens
            .lock()
            .map_err(poisoned)?
            .values()
            .cloned()
            .collect();
        tokens.sort_by(|a, b| a.issued_at.cmp(&b.issued_at).then(a.id.cmp(&b.id)));
        Ok(tokens)
    }
}

/// A consent that answers every ask the same way; for tests and for a node
/// with nobody to ask.
#[derive(Clone, Copy, Debug)]
pub struct Always(pub Answer);

impl Consent for Always {
    fn ask(&self, _ask: &Ask) -> Result<(), OAuthError> {
        Ok(())
    }

    fn answer(&self, _ask: &Ask) -> Result<Answer, OAuthError> {
        Ok(self.0)
    }
}

// --- The wire shapes ---

/// RFC 7591: what a client says about itself. Anything else it sends is
/// ignored.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Registration {
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

/// RFC 7591: the client as registered. The auth method is `none`: public
/// clients, PKCE is the proof.
#[derive(Clone, Debug, Serialize)]
pub struct Registered {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub client_id_issued_at: u64,
    pub token_endpoint_auth_method: &'static str,
    pub grant_types: [&'static str; 1],
    pub response_types: [&'static str; 1],
}

impl From<Client> for Registered {
    fn from(client: Client) -> Self {
        Self {
            client_id: client.id,
            client_name: client.name,
            redirect_uris: client.redirect_uris,
            client_id_issued_at: client.registered_at,
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code"],
            response_types: ["code"],
        }
    }
}

/// Why a registration was refused (RFC 7591 §3.2.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegistrationRefusal {
    pub error: &'static str,
    pub error_description: String,
}

/// The query a client sends the person to `/oauth/authorize` with.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Why an authorize request went no further. When the client and its
/// redirect are known the refusal rides back to the client on that redirect
/// (RFC 6749 §4.1.2.1); otherwise it is a page for the person, since sending
/// them to an address nobody registered is the attack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Page { status: u16, message: String },
    Redirect(String),
}

/// Where an ask stands, as the waiting page polls it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    Waiting,
    /// Let in: send the person back to the client with the code.
    Redirect(String),
    /// Not let in: send the person back with `access_denied`.
    Denied(String),
    /// Unknown, expired, or already redeemed.
    Gone,
}

/// What a client posts to `/oauth/token`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
}

/// A token, shown once. It does not expire; the person revokes it from Proxy.
#[derive(Clone, Debug, Serialize)]
pub struct Issued {
    pub access_token: String,
    pub token_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// RFC 6749 §5.2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenRefusal {
    pub error: &'static str,
    pub error_description: String,
}

impl TokenRefusal {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: description.into(),
        }
    }

    /// The status the refusal is sent with: 401 for a client it does not
    /// know, 400 for everything else (RFC 6749 §5.2).
    pub fn status(&self) -> u16 {
        if self.error == "invalid_client" {
            401
        } else {
            400
        }
    }
}

/// RFC 8414, as far as this server goes.
#[derive(Clone, Debug, Serialize)]
pub struct ServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: [&'static str; 1],
    pub grant_types_supported: [&'static str; 1],
    pub code_challenge_methods_supported: [&'static str; 1],
    pub token_endpoint_auth_methods_supported: [&'static str; 1],
    pub revocation_endpoint_auth_methods_supported: [&'static str; 1],
}

/// RFC 9728: the resource names the server that guards it, which is itself.
#[derive(Clone, Debug, Serialize)]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: [String; 1],
    pub bearer_methods_supported: [&'static str; 1],
}

pub fn server_metadata(issuer: &str) -> ServerMetadata {
    let issuer = issuer.trim_end_matches('/').to_string();
    ServerMetadata {
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        registration_endpoint: format!("{issuer}/oauth/register"),
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        issuer,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        revocation_endpoint_auth_methods_supported: ["none"],
    }
}

pub fn resource_metadata(issuer: &str) -> ResourceMetadata {
    let issuer = issuer.trim_end_matches('/').to_string();
    ResourceMetadata {
        resource: issuer.clone(),
        authorization_servers: [issuer],
        bearer_methods_supported: ["header"],
    }
}

/// The `WWW-Authenticate` value a 401 carries so a client finds its way to
/// `/oauth/authorize` (RFC 9728 §5.1).
pub fn www_authenticate(issuer: &str) -> String {
    let issuer = issuer.trim_end_matches('/');
    format!("Bearer resource_metadata=\"{issuer}/.well-known/oauth-protected-resource\"")
}

// --- The server ---

/// The authorization server: a [`Store`] and a [`Consent`], and the rules
/// between them. Clocks are the caller's (`now`, seconds since the epoch) so
/// every rule is testable.
pub struct Server<S: Store, C: Consent> {
    store: S,
    consent: C,
}

impl<S: Store, C: Consent> Server<S, C> {
    pub fn new(store: S, consent: C) -> Self {
        Self { store, consent }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn consent(&self) -> &C {
        &self.consent
    }

    /// RFC 7591. A client needs a name the person will recognise and at
    /// least one redirect it may be sent back to: `https://`, or `http://`
    /// on the loopback for a client running on the person's own machine.
    pub fn register(
        &self,
        registration: Registration,
        now: u64,
    ) -> Result<Result<Client, RegistrationRefusal>, OAuthError> {
        let name = registration
            .client_name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty());
        let Some(name) = name else {
            return Ok(Err(RegistrationRefusal {
                error: "invalid_client_metadata",
                error_description:
                    "client_name is required: the person is asked whether to let it in by that name"
                        .to_string(),
            }));
        };
        if name.chars().count() > 80 {
            return Ok(Err(RegistrationRefusal {
                error: "invalid_client_metadata",
                error_description: "client_name is at most 80 characters".to_string(),
            }));
        }
        if registration.redirect_uris.is_empty() {
            return Ok(Err(RegistrationRefusal {
                error: "invalid_redirect_uri",
                error_description: "redirect_uris is required".to_string(),
            }));
        }
        for uri in &registration.redirect_uris {
            if !redirect_uri_is_allowed(uri) {
                return Ok(Err(RegistrationRefusal {
                    error: "invalid_redirect_uri",
                    error_description: format!(
                        "{uri} is not an https URL or an http URL on the loopback, or it has a fragment"
                    ),
                }));
            }
        }
        let client = Client {
            id: random_hex(16),
            name,
            redirect_uris: registration.redirect_uris,
            registered_at: now,
        };
        self.store.put_client(&client)?;
        Ok(Ok(client))
    }

    /// RFC 6749 §4.1.1 with PKCE (RFC 7636, S256 only). A good request
    /// becomes an [`Ask`] the [`Consent`] puts in front of the person.
    /// `issuer` is the address asked, which every answer names.
    pub fn authorize(
        &self,
        request: AuthorizeRequest,
        issuer: &str,
        now: u64,
    ) -> Result<Result<Ask, Refusal>, OAuthError> {
        let issuer = issuer.trim_end_matches('/');
        let page = |message: &str| {
            Ok(Err(Refusal::Page {
                status: 400,
                message: message.to_string(),
            }))
        };
        let Some(client_id) = request
            .client_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
        else {
            return page("The request names no client_id.");
        };
        let Some(client) = self.store.client(client_id)? else {
            return page("No client with that client_id has registered here.");
        };
        let Some(redirect_uri) = request
            .redirect_uri
            .as_deref()
            .map(str::trim)
            .filter(|uri| !uri.is_empty())
        else {
            return page("The request names no redirect_uri.");
        };
        if !client
            .redirect_uris
            .iter()
            .any(|known| known == redirect_uri)
        {
            return page("The redirect_uri is not one the client registered.");
        }
        // From here the client is known, so a refusal rides back to it.
        let refuse = |error: &str, description: &str| {
            Ok(Err(Refusal::Redirect(redirect_with(
                redirect_uri,
                &[
                    ("error", error),
                    ("error_description", description),
                    ("state", request.state.as_deref().unwrap_or("")),
                    ("iss", issuer),
                ],
            ))))
        };
        if request.response_type.as_deref().map(str::trim) != Some("code") {
            return refuse(
                "unsupported_response_type",
                "Only response_type=code is supported.",
            );
        }
        if request
            .code_challenge_method
            .as_deref()
            .map(str::trim)
            .unwrap_or("S256")
            != "S256"
        {
            return refuse(
                "invalid_request",
                "Only code_challenge_method=S256 is supported.",
            );
        }
        let Some(code_challenge) = request
            .code_challenge
            .as_deref()
            .map(str::trim)
            .filter(|c| code_challenge_is_well_formed(c))
        else {
            return refuse(
                "invalid_request",
                "PKCE is required: send a code_challenge of 43 to 128 unreserved characters.",
            );
        };
        let ask = Ask {
            id: random_hex(16),
            client_id: client.id,
            client_name: client.name,
            issuer: issuer.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: request
                .scope
                .map(|scope| scope.trim().to_string())
                .filter(|scope| !scope.is_empty()),
            state: request.state.filter(|state| !state.is_empty()),
            code_challenge: code_challenge.to_string(),
            asked_at: now,
            code: None,
            code_issued_at: None,
            code_used: false,
        };
        self.store.put_ask(&ask)?;
        self.consent.ask(&ask)?;
        Ok(Ok(ask))
    }

    /// Where an ask stands. The first poll after the person lets the client
    /// in mints the code; later polls return the same redirect until the code
    /// is redeemed.
    pub fn progress(&self, ask_id: &str, now: u64) -> Result<Progress, OAuthError> {
        let Some(mut ask) = self.store.ask(ask_id)? else {
            return Ok(Progress::Gone);
        };
        if ask.code_used {
            return Ok(Progress::Gone);
        }
        if let Some(code) = ask.code.as_deref() {
            return Ok(if code_is_fresh(&ask, now) {
                Progress::Redirect(approved_redirect(&ask, code))
            } else {
                Progress::Gone
            });
        }
        if now.saturating_sub(ask.asked_at) > ASK_TTL_SECS {
            return Ok(Progress::Gone);
        }
        match self.consent.answer(&ask)? {
            Answer::Pending => Ok(Progress::Waiting),
            Answer::Denied => Ok(Progress::Denied(redirect_with(
                &ask.redirect_uri,
                &[
                    ("error", "access_denied"),
                    ("error_description", "The person did not let the client in."),
                    ("state", ask.state.as_deref().unwrap_or("")),
                    ("iss", &ask.issuer),
                ],
            ))),
            Answer::Approved => {
                let code = random_hex(24);
                ask.code = Some(code.clone());
                ask.code_issued_at = Some(now);
                self.store.put_ask(&ask)?;
                Ok(Progress::Redirect(approved_redirect(&ask, &code)))
            }
        }
    }

    /// RFC 6749 §4.1.3 with the PKCE check (RFC 7636 §4.6). A code is
    /// redeemed once, within [`CODE_TTL_SECS`], by the client that asked, at
    /// the redirect it asked with, with the verifier its challenge came from.
    pub fn token(
        &self,
        request: TokenRequest,
        now: u64,
    ) -> Result<Result<Issued, TokenRefusal>, OAuthError> {
        if request.grant_type.as_deref().map(str::trim) != Some("authorization_code") {
            return Ok(Err(TokenRefusal::new(
                "unsupported_grant_type",
                "Only grant_type=authorization_code is supported.",
            )));
        }
        let Some(code) = request
            .code
            .as_deref()
            .map(str::trim)
            .filter(|code| !code.is_empty())
        else {
            return Ok(Err(TokenRefusal::new(
                "invalid_request",
                "code is required.",
            )));
        };
        let Some(verifier) = request
            .code_verifier
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return Ok(Err(TokenRefusal::new(
                "invalid_request",
                "code_verifier is required.",
            )));
        };
        let Some(mut ask) = self.store.ask_by_code(code)? else {
            return Ok(Err(TokenRefusal::new(
                "invalid_grant",
                "The code is not one this server issued.",
            )));
        };
        if ask.code_used || !code_is_fresh(&ask, now) {
            return Ok(Err(TokenRefusal::new(
                "invalid_grant",
                "The code was already redeemed, or is older than ten minutes.",
            )));
        }
        if request.client_id.as_deref().map(str::trim) != Some(ask.client_id.as_str()) {
            return Ok(Err(TokenRefusal::new(
                "invalid_client",
                "The client_id is not the one that asked.",
            )));
        }
        if request.redirect_uri.as_deref().map(str::trim) != Some(ask.redirect_uri.as_str()) {
            return Ok(Err(TokenRefusal::new(
                "invalid_grant",
                "The redirect_uri is not the one the ask was made with.",
            )));
        }
        if !pkce_matches(verifier, &ask.code_challenge) {
            return Ok(Err(TokenRefusal::new(
                "invalid_grant",
                "The code_verifier does not match the code_challenge.",
            )));
        }
        ask.code_used = true;
        self.store.put_ask(&ask)?;
        let secret = random_hex(32);
        let token = Token {
            id: random_hex(16),
            client_id: ask.client_id,
            client_name: ask.client_name,
            hash: hash_token(&secret),
            scope: ask.scope.clone(),
            issued_at: now,
            last_used_at: None,
            revoked_at: None,
        };
        self.store.put_token(&token)?;
        Ok(Ok(Issued {
            access_token: secret,
            token_type: "Bearer",
            scope: ask.scope,
        }))
    }

    /// RFC 7009. A token nobody holds revokes to nothing, and that is fine.
    pub fn revoke(&self, bearer: &str, now: u64) -> Result<(), OAuthError> {
        if let Some(token) = self.store.token_by_hash(&hash_token(bearer.trim()))? {
            self.revoke_token(token, now)?;
        }
        Ok(())
    }

    /// Take a token back from Proxy, by id. `false` when there is no such
    /// token.
    pub fn revoke_id(&self, id: &str, now: u64) -> Result<bool, OAuthError> {
        match self.store.token(id)? {
            Some(token) => {
                self.revoke_token(token, now)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn revoke_token(&self, mut token: Token, now: u64) -> Result<(), OAuthError> {
        if token.revoked_at.is_none() {
            token.revoked_at = Some(now);
            self.store.put_token(&token)?;
        }
        Ok(())
    }

    /// The token behind a bearer, if it is one this server issued and still
    /// live. Marks it used, at most once a minute, through
    /// [`Store::touch_token`]: only `last_used_at` is written, never the row
    /// this request read, so a revoke that lands while the request is in
    /// flight stays a revoke.
    pub fn admit(&self, bearer: &str, now: u64) -> Result<Option<Token>, OAuthError> {
        let bearer = bearer.trim();
        if bearer.is_empty() {
            return Ok(None);
        }
        let Some(mut token) = self.store.token_by_hash(&hash_token(bearer))? else {
            return Ok(None);
        };
        if !token.is_live() {
            return Ok(None);
        }
        if token
            .last_used_at
            .is_none_or(|used| now.saturating_sub(used) >= TOUCH_EVERY_SECS)
        {
            token.last_used_at = Some(now);
            self.store.touch_token(&token.id, now)?;
        }
        Ok(Some(token))
    }

    /// The tokens still out: what Proxy lists as connected, newest last.
    pub fn connections(&self) -> Result<Vec<Token>, OAuthError> {
        Ok(self
            .store
            .tokens()?
            .into_iter()
            .filter(Token::is_live)
            .collect())
    }
}

// --- The rules ---

/// OAuth 2.1 §1.5 and RFC 8252 §7.3: `https`, or `http` on the loopback,
/// with no fragment.
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
    let digest = Sha256::digest(verifier.as_bytes());
    constant_time_eq(base64url(&digest).as_bytes(), challenge.as_bytes())
}

/// What is kept of a token: the hex SHA-256 of the bearer string.
pub fn hash_token(bearer: &str) -> String {
    encode_hex(&Sha256::digest(bearer.as_bytes()))
}

/// `n` random bytes as lowercase hex.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

fn code_is_fresh(ask: &Ask, now: u64) -> bool {
    ask.code_issued_at
        .is_some_and(|issued| now.saturating_sub(issued) <= CODE_TTL_SECS)
}

/// The answer to an ask that was let in: the code and the state, the issuer
/// (RFC 9207), and the client's id, for a client that never saw the
/// address before Proxy sent it back here.
fn approved_redirect(ask: &Ask, code: &str) -> String {
    redirect_with(
        &ask.redirect_uri,
        &[
            ("code", code),
            ("state", ask.state.as_deref().unwrap_or("")),
            ("iss", &ask.issuer),
            ("client_id", &ask.client_id),
        ],
    )
}

/// The redirect with these query parameters added; an empty value is left
/// out, so a client that sent no `state` gets none back.
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
        url.push_str(&encode_component(value));
        separator = '&';
    }
    url
}

/// Percent-encoding for a query value: everything but the unreserved set.
pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4).to_ascii_uppercase());
            out.push(hex_digit(byte & 0x0f).to_ascii_uppercase());
        }
    }
    out
}

/// Base64url without padding (RFC 4648 §5), as PKCE wants it.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0f));
    }
    encoded
}

fn hex_digit(nibble: u8) -> char {
    b"0123456789abcdef"[nibble as usize] as char
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn challenge_of(verifier: &str) -> String {
        base64url(&Sha256::digest(verifier.as_bytes()))
    }

    fn server(answer: Answer) -> Server<MemoryStore, Always> {
        Server::new(MemoryStore::new(), Always(answer))
    }

    fn registered(server: &Server<MemoryStore, Always>) -> Client {
        server
            .register(
                Registration {
                    client_name: Some("Claude".to_string()),
                    redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
                },
                NOW,
            )
            .unwrap()
            .unwrap()
    }

    const ISSUER: &str = "https://jckwind.proxy.ing";

    fn asked(server: &Server<MemoryStore, Always>, client: &Client) -> Ask {
        server
            .authorize(
                AuthorizeRequest {
                    response_type: Some("code".to_string()),
                    client_id: Some(client.id.clone()),
                    redirect_uri: Some(client.redirect_uris[0].clone()),
                    scope: None,
                    state: Some("xyz".to_string()),
                    code_challenge: Some(challenge_of(VERIFIER)),
                    code_challenge_method: Some("S256".to_string()),
                },
                ISSUER,
                NOW,
            )
            .unwrap()
            .unwrap()
    }

    fn code_in(redirect: &str) -> String {
        redirect
            .split(['?', '&'])
            .find_map(|pair| pair.strip_prefix("code="))
            .unwrap()
            .to_string()
    }

    fn redeem(
        server: &Server<MemoryStore, Always>,
        client: &Client,
        code: &str,
        verifier: &str,
        at: u64,
    ) -> Result<Issued, TokenRefusal> {
        server
            .token(
                TokenRequest {
                    grant_type: Some("authorization_code".to_string()),
                    code: Some(code.to_string()),
                    redirect_uri: Some(client.redirect_uris[0].clone()),
                    client_id: Some(client.id.clone()),
                    code_verifier: Some(verifier.to_string()),
                },
                at,
            )
            .unwrap()
    }

    #[test]
    fn pkce_s256_matches_the_rfc_7636_example() {
        assert_eq!(
            challenge_of(VERIFIER),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(pkce_matches(
            VERIFIER,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_matches(
            "not-the-verifier-but-long-enough-to-be-well-formed-ok",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_matches(
            "short",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn base64url_is_unpadded_and_url_safe() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn a_redirect_is_https_or_loopback_http_with_no_fragment() {
        assert!(redirect_uri_is_allowed(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(redirect_uri_is_allowed("http://localhost:52341/callback"));
        assert!(redirect_uri_is_allowed("http://127.0.0.1/callback"));
        assert!(!redirect_uri_is_allowed("http://example.com/callback"));
        assert!(!redirect_uri_is_allowed("https://claude.ai/cb#fragment"));
        assert!(!redirect_uri_is_allowed("custom://callback"));
        assert!(!redirect_uri_is_allowed("https:///nohost"));
    }

    #[test]
    fn registration_needs_a_name_and_an_allowed_redirect() {
        let server = server(Answer::Pending);
        let nameless = server
            .register(
                Registration {
                    client_name: None,
                    redirect_uris: vec!["https://a.example/cb".to_string()],
                },
                NOW,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(nameless.error, "invalid_client_metadata");
        let elsewhere = server
            .register(
                Registration {
                    client_name: Some("X".to_string()),
                    redirect_uris: vec!["http://evil.example/cb".to_string()],
                },
                NOW,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(elsewhere.error, "invalid_redirect_uri");
        let client = registered(&server);
        assert_eq!(client.name, "Claude");
        assert_eq!(server.store().client(&client.id).unwrap().unwrap(), client);
        let shown = Registered::from(client);
        assert_eq!(shown.token_endpoint_auth_method, "none");
        assert_eq!(shown.grant_types, ["authorization_code"]);
    }

    #[test]
    fn an_unknown_client_or_redirect_is_a_page_and_never_a_redirect() {
        let server = server(Answer::Pending);
        let client = registered(&server);
        let unknown = server
            .authorize(
                AuthorizeRequest {
                    client_id: Some("nope".to_string()),
                    redirect_uri: Some("https://evil.example/".to_string()),
                    ..Default::default()
                },
                ISSUER,
                NOW,
            )
            .unwrap()
            .unwrap_err();
        assert!(matches!(unknown, Refusal::Page { status: 400, .. }));
        let elsewhere = server
            .authorize(
                AuthorizeRequest {
                    client_id: Some(client.id.clone()),
                    redirect_uri: Some("https://evil.example/".to_string()),
                    ..Default::default()
                },
                ISSUER,
                NOW,
            )
            .unwrap()
            .unwrap_err();
        assert!(matches!(elsewhere, Refusal::Page { .. }));
    }

    #[test]
    fn a_known_client_without_pkce_is_refused_on_its_redirect_with_its_state() {
        let server = server(Answer::Pending);
        let client = registered(&server);
        let refused = server
            .authorize(
                AuthorizeRequest {
                    response_type: Some("code".to_string()),
                    client_id: Some(client.id.clone()),
                    redirect_uri: Some(client.redirect_uris[0].clone()),
                    state: Some("s 1".to_string()),
                    ..Default::default()
                },
                ISSUER,
                NOW,
            )
            .unwrap()
            .unwrap_err();
        let Refusal::Redirect(url) = refused else {
            panic!("{refused:?}")
        };
        assert!(
            url.starts_with("https://claude.ai/api/mcp/auth_callback?error=invalid_request&"),
            "{url}"
        );
        assert!(
            url.contains("&state=s%201&iss=https%3A%2F%2Fjckwind.proxy.ing"),
            "{url}"
        );
        let plain = server
            .authorize(
                AuthorizeRequest {
                    response_type: Some("code".to_string()),
                    client_id: Some(client.id.clone()),
                    redirect_uri: Some(client.redirect_uris[0].clone()),
                    code_challenge: Some(challenge_of(VERIFIER)),
                    code_challenge_method: Some("plain".to_string()),
                    ..Default::default()
                },
                ISSUER,
                NOW,
            )
            .unwrap()
            .unwrap_err();
        assert!(matches!(plain, Refusal::Redirect(url) if url.contains("error=invalid_request")));
    }

    #[test]
    fn the_person_lets_it_in_and_the_client_redeems_the_code_once() {
        let server = server(Answer::Approved);
        let client = registered(&server);
        let ask = asked(&server, &client);
        assert_eq!(ask.client_name, "Claude");
        assert_eq!(ask.state.as_deref(), Some("xyz"));

        let Progress::Redirect(redirect) = server.progress(&ask.id, NOW + 5).unwrap() else {
            panic!()
        };
        assert!(
            redirect.starts_with("https://claude.ai/api/mcp/auth_callback?code="),
            "{redirect}"
        );
        assert!(
            redirect.contains(&format!(
                "&state=xyz&iss=https%3A%2F%2Fjckwind.proxy.ing&client_id={}",
                client.id
            )),
            "{redirect}"
        );
        // The same code until it is redeemed.
        assert_eq!(
            server.progress(&ask.id, NOW + 6).unwrap(),
            Progress::Redirect(redirect.clone())
        );

        let code = code_in(&redirect);
        let issued = redeem(&server, &client, &code, VERIFIER, NOW + 10).unwrap();
        assert_eq!(issued.token_type, "Bearer");
        assert_eq!(issued.access_token.len(), 64);

        // Redeemed: the ask is gone, the code is dead, the token is live.
        assert_eq!(server.progress(&ask.id, NOW + 11).unwrap(), Progress::Gone);
        assert_eq!(
            redeem(&server, &client, &code, VERIFIER, NOW + 12)
                .unwrap_err()
                .error,
            "invalid_grant"
        );
        let token = server
            .admit(&issued.access_token, NOW + 20)
            .unwrap()
            .unwrap();
        assert_eq!(token.client_name, "Claude");
        assert_eq!(token.last_used_at, Some(NOW + 20));
        assert_eq!(server.connections().unwrap().len(), 1);
    }

    #[test]
    fn a_code_is_bound_to_the_verifier_the_client_and_the_redirect_and_ten_minutes() {
        let server = server(Answer::Approved);
        let client = registered(&server);
        let ask = asked(&server, &client);
        let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
            panic!()
        };
        let code = code_in(&redirect);

        let wrong_verifier = redeem(
            &server,
            &client,
            &code,
            "wrong-verifier-that-is-long-enough-to-be-well-formed-x",
            NOW + 1,
        )
        .unwrap_err();
        assert_eq!(wrong_verifier.error, "invalid_grant");

        let other = Client {
            id: "other".to_string(),
            ..client.clone()
        };
        let wrong_client = redeem(&server, &other, &code, VERIFIER, NOW + 1).unwrap_err();
        assert_eq!(wrong_client.error, "invalid_client");
        assert_eq!(wrong_client.status(), 401);

        let elsewhere = Client {
            redirect_uris: vec!["https://claude.ai/other".to_string()],
            ..client.clone()
        };
        assert_eq!(
            redeem(&server, &elsewhere, &code, VERIFIER, NOW + 1)
                .unwrap_err()
                .error,
            "invalid_grant"
        );

        let late = redeem(&server, &client, &code, VERIFIER, NOW + CODE_TTL_SECS + 1).unwrap_err();
        assert_eq!(late.error, "invalid_grant");
        // Late, the waiting page is told it is gone too.
        assert_eq!(
            server.progress(&ask.id, NOW + CODE_TTL_SECS + 1).unwrap(),
            Progress::Gone
        );
    }

    #[test]
    fn nobody_answering_is_waiting_then_gone_and_no_is_access_denied() {
        let waiting = server(Answer::Pending);
        let client = registered(&waiting);
        let ask = asked(&waiting, &client);
        assert_eq!(
            waiting.progress(&ask.id, NOW + 60).unwrap(),
            Progress::Waiting
        );
        assert_eq!(
            waiting.progress(&ask.id, NOW + ASK_TTL_SECS + 1).unwrap(),
            Progress::Gone
        );
        assert_eq!(waiting.progress("nope", NOW).unwrap(), Progress::Gone);

        let denied = server(Answer::Denied);
        let client = registered(&denied);
        let ask = asked(&denied, &client);
        let Progress::Denied(url) = denied.progress(&ask.id, NOW).unwrap() else {
            panic!()
        };
        assert!(url.contains("error=access_denied"), "{url}");
        assert!(
            url.contains("&state=xyz&iss=https%3A%2F%2Fjckwind.proxy.ing"),
            "{url}"
        );
    }

    #[test]
    fn a_revoked_token_is_not_admitted_and_is_no_longer_a_connection() {
        let server = server(Answer::Approved);
        let client = registered(&server);
        let ask = asked(&server, &client);
        let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
            panic!()
        };
        let issued = redeem(&server, &client, &code_in(&redirect), VERIFIER, NOW).unwrap();
        let token = server.admit(&issued.access_token, NOW).unwrap().unwrap();

        // Admission touches at most once a minute.
        assert_eq!(
            server
                .admit(&issued.access_token, NOW + 30)
                .unwrap()
                .unwrap()
                .last_used_at,
            Some(NOW)
        );
        assert_eq!(
            server
                .admit(&issued.access_token, NOW + 61)
                .unwrap()
                .unwrap()
                .last_used_at,
            Some(NOW + 61)
        );

        server.revoke(&issued.access_token, NOW + 100).unwrap();
        assert_eq!(server.admit(&issued.access_token, NOW + 101).unwrap(), None);
        assert!(server.connections().unwrap().is_empty());
        assert_eq!(
            server.store().token(&token.id).unwrap().unwrap().revoked_at,
            Some(NOW + 100)
        );
        // Revoking what nobody holds is fine, and by id says whether there was one.
        server.revoke("nothing", NOW).unwrap();
        assert!(!server.revoke_id("nothing", NOW).unwrap());
        assert_eq!(server.admit("", NOW).unwrap(), None);
    }

    /// Alex's finding on root PR 45: a request admitted just before the
    /// person removed the connection used to write its whole token row back,
    /// `revoked_at` and all, and the connection came back. Now the in-flight
    /// write touches only a live token's `last_used_at`, and a put can never
    /// clear a revocation.
    #[test]
    fn a_request_in_flight_across_a_revoke_cannot_restore_the_connection() {
        let server = server(Answer::Approved);
        let client = registered(&server);
        let ask = asked(&server, &client);
        let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
            panic!()
        };
        let issued = redeem(&server, &client, &code_in(&redirect), VERIFIER, NOW).unwrap();

        // The request reads the token while it is live...
        let in_flight = server
            .store()
            .token_by_hash(&hash_token(&issued.access_token))
            .unwrap()
            .unwrap();
        assert!(in_flight.is_live());
        // ...the person removes the connection...
        server.revoke(&issued.access_token, NOW + 10).unwrap();
        // ...and the request then records its last use, both ways it could.
        server.store().touch_token(&in_flight.id, NOW + 11).unwrap();
        let mut stale = in_flight.clone();
        stale.last_used_at = Some(NOW + 11);
        server.store().put_token(&stale).unwrap();

        assert_eq!(server.admit(&issued.access_token, NOW + 12).unwrap(), None);
        assert!(server.connections().unwrap().is_empty());
        let held = server.store().token(&in_flight.id).unwrap().unwrap();
        assert_eq!(held.revoked_at, Some(NOW + 10));
        assert_eq!(held.last_used_at, None, "a revoked token is not touched");
        // Touching what does not exist is nothing.
        server.store().touch_token("nothing", NOW).unwrap();
    }

    #[test]
    fn the_metadata_points_at_the_issuer_and_the_401_points_at_the_metadata() {
        let metadata = server_metadata("https://jckwind.proxy.ing/");
        assert_eq!(metadata.issuer, "https://jckwind.proxy.ing");
        assert_eq!(
            metadata.authorization_endpoint,
            "https://jckwind.proxy.ing/oauth/authorize"
        );
        assert_eq!(
            metadata.token_endpoint,
            "https://jckwind.proxy.ing/oauth/token"
        );
        assert_eq!(
            metadata.registration_endpoint,
            "https://jckwind.proxy.ing/oauth/register"
        );
        assert_eq!(metadata.code_challenge_methods_supported, ["S256"]);
        let resource = resource_metadata("https://jckwind.proxy.ing");
        assert_eq!(
            resource.authorization_servers,
            ["https://jckwind.proxy.ing".to_string()]
        );
        assert_eq!(
            www_authenticate("https://jckwind.proxy.ing"),
            "Bearer resource_metadata=\"https://jckwind.proxy.ing/.well-known/oauth-protected-resource\""
        );
    }

    #[test]
    fn redirects_keep_the_query_the_client_had_and_encode_what_they_add() {
        assert_eq!(
            redirect_with(
                "https://a.example/cb?x=1",
                &[("code", "c d"), ("state", "")]
            ),
            "https://a.example/cb?x=1&code=c%20d"
        );
        assert_eq!(
            redirect_with(
                "http://localhost:1/cb",
                &[("error", "access_denied"), ("state", "a&b")]
            ),
            "http://localhost:1/cb?error=access_denied&state=a%26b"
        );
    }
}
