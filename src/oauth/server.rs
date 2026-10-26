//! OAuth wire types, metadata builders, and authorization [`Server`] state
//! machine.

use serde::{Deserialize, Serialize};

use super::store::{Consent, Store};
use super::{
    ASK_TTL_SECS, AUTHORIZE_LIMIT, Answer, Ask, CODE_TTL_SECS, Client, DEFAULT_SCOPE, FAMILIES,
    Limiter, OAuthError, REGISTER_LIMIT, TOKEN_TTL_SECS, TOUCH_EVERY_SECS, Token,
    code_challenge_is_well_formed, expires_at_for, hash_token, normalize_scope, pkce_matches,
    random_hex, redirect_uri_is_allowed, redirect_with,
};

/// RFC 7591 client registration request body.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Registration {
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

/// RFC 7591 registered client metadata response.
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

/// RFC 7591 §3.2.2 registration refusal response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegistrationRefusal {
    pub error: &'static str,
    pub error_description: String,
}

/// Query parameters sent to `/oauth/authorize`.
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

/// Why an authorize request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Page { status: u16, message: String },
    Redirect(String),
}

/// Poll status of an authorization [`Ask`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    Waiting,
    Redirect(String),
    Denied(String),
    Gone,
}

/// Form body posted to `/oauth/token`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
}

/// RFC 6749 §5.1 token response.
#[derive(Clone, Debug, Serialize)]
pub struct Issued {
    pub access_token: String,
    pub token_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    pub scope: String,
}

/// RFC 6749 §5.2 token error response.
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

    pub fn status(&self) -> u16 {
        if self.error == "invalid_client" {
            401
        } else {
            400
        }
    }
}

/// RFC 8414 authorization server metadata.
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
    pub scopes_supported: [&'static str; 8],
}

/// RFC 9728 protected resource metadata.
#[derive(Clone, Debug, Serialize)]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: [String; 1],
    pub bearer_methods_supported: [&'static str; 1],
    pub scopes_supported: [&'static str; 8],
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
        scopes_supported: FAMILIES,
    }
}

pub fn resource_metadata(issuer: &str) -> ResourceMetadata {
    let issuer = issuer.trim_end_matches('/').to_string();
    ResourceMetadata {
        resource: issuer.clone(),
        authorization_servers: [issuer],
        bearer_methods_supported: ["header"],
        scopes_supported: FAMILIES,
    }
}

/// `WWW-Authenticate` header value for 401 responses (RFC 9728 §5.1 / RFC 6750 §3).
pub fn www_authenticate(issuer: &str, scope: Option<&str>) -> String {
    let issuer = issuer.trim_end_matches('/');
    let mut value =
        format!("Bearer resource_metadata=\"{issuer}/.well-known/oauth-protected-resource\"");
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        value.push_str(&format!(", scope=\"{scope}\""));
    }
    value
}

/// `WWW-Authenticate` header value for 403 `insufficient_scope` responses (RFC 6750 §3.1).
pub fn insufficient_scope(issuer: &str, scope: &str) -> String {
    let issuer = issuer.trim_end_matches('/');
    format!(
        "Bearer error=\"insufficient_scope\", scope=\"{scope}\", \
         resource_metadata=\"{issuer}/.well-known/oauth-protected-resource\""
    )
}

/// Authorization server state machine over a [`Store`] and [`Consent`].
pub struct Server<S: Store, C: Consent> {
    store: S,
    consent: C,
    registers: Limiter,
    asks: Limiter,
}

impl<S: Store, C: Consent> Server<S, C> {
    pub fn new(store: S, consent: C) -> Self {
        Self {
            store,
            consent,
            registers: Limiter::new(REGISTER_LIMIT.0, REGISTER_LIMIT.1),
            asks: Limiter::new(AUTHORIZE_LIMIT.0, AUTHORIZE_LIMIT.1),
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn consent(&self) -> &C {
        &self.consent
    }

    pub fn may_register(&self, source: &str, now: u64) -> bool {
        self.registers.allow(source, now)
    }

    pub fn may_ask(&self, source: &str, now: u64) -> bool {
        self.asks.allow(source, now)
    }

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
        let scope = match normalize_scope(request.scope.as_deref()) {
            Ok(scope) => scope,
            Err(why) => return refuse("invalid_scope", &why),
        };
        let ask = Ask {
            id: random_hex(16),
            client_id: client.id,
            client_name: client.name,
            issuer: issuer.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: Some(scope),
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

    pub fn progress(&self, ask_id: &str, now: u64) -> Result<Progress, OAuthError> {
        let Some(ask) = self.store.ask(ask_id)? else {
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
                let Some(ask) = self.store.mint_code(&ask.id, &random_hex(24), now)? else {
                    return Ok(Progress::Gone);
                };
                Ok(match ask.code.as_deref() {
                    Some(code) if code_is_fresh(&ask, now) => {
                        Progress::Redirect(approved_redirect(&ask, code))
                    }
                    _ => Progress::Gone,
                })
            }
        }
    }

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
        let Some(ask) = self.store.redeem_code(code)? else {
            return Ok(Err(TokenRefusal::new(
                "invalid_grant",
                "The code is not one this server issued, or it was already redeemed.",
            )));
        };
        if !code_is_fresh(&ask, now) {
            return Ok(Err(TokenRefusal::new(
                "invalid_grant",
                "The code is older than ten minutes.",
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
        let secret = random_hex(32);
        let scope = ask.scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
        let token = Token {
            id: random_hex(16),
            client_id: ask.client_id,
            client_name: ask.client_name,
            hash: hash_token(&secret),
            scope: Some(scope.clone()),
            issued_at: now,
            expires_at: expires_at_for(&scope, now),
            last_used_at: None,
            revoked_at: None,
        };
        self.store.put_token(&token)?;
        Ok(Ok(Issued {
            access_token: secret,
            token_type: "Bearer",
            expires_in: token.runs_out().then_some(TOKEN_TTL_SECS),
            scope,
        }))
    }

    pub fn revoke(&self, bearer: &str, now: u64) -> Result<(), OAuthError> {
        if let Some(token) = self.store.token_by_hash(&hash_token(bearer.trim()))? {
            self.store.revoke_token(&token.id, now)?;
        }
        Ok(())
    }

    pub fn admit(&self, bearer: &str, now: u64) -> Result<Option<Token>, OAuthError> {
        let bearer = bearer.trim();
        if bearer.is_empty() {
            return Ok(None);
        }
        let Some(mut token) = self.store.token_by_hash(&hash_token(bearer))? else {
            return Ok(None);
        };
        if !token.is_live_at(now) {
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
}

fn code_is_fresh(ask: &Ask, now: u64) -> bool {
    ask.code_issued_at
        .is_some_and(|issued| now.saturating_sub(issued) <= CODE_TTL_SECS)
}

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
