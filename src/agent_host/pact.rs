//! PACT 1.0 personal-agent client and ES256 identity. Wire requirements are
//! from https://openpactprotocol.org/spec.md, not the unrelated PAP acronym.
//! Login belongs to the Brand: this code returns its URL and never observes it.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use reqwest::{Client, Url};
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde_json::{Value, json};

use super::HostError;
use crate::DeviceIdentity;

pub const PACT_SPEC: &str = "https://openpactprotocol.org/spec.md";

pub struct PactIdentity {
    pub issuer: String,
    key: Arc<DeviceIdentity>,
    kid: String,
}

impl PactIdentity {
    pub fn new(issuer: String, key: Arc<DeviceIdentity>) -> Result<Self, HostError> {
        checked_url(&issuer)?;
        if issuer.ends_with('/') {
            return Err(HostError::Invalid(
                "issuer must be the exact canonical URL without a trailing slash".into(),
            ));
        }
        let kid = key.device_id().to_hex();
        Ok(Self { issuer, key, kid })
    }
    pub fn jwks(&self) -> Value {
        let point = self.key.verifying_key().to_encoded_point(false);
        json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":self.kid,
            "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}]})
    }
    pub fn token(&self, subject: &str, audience: &str, now: u64) -> Result<String, HostError> {
        if subject.is_empty() || subject.len() > 256 || subject.contains('@') || audience.is_empty()
        {
            return Err(HostError::Invalid(
                "PACT needs a stable opaque subject and the provider-assigned audience".into(),
            ));
        }
        self.sign_claims(&json!({"iss":self.issuer,"sub":subject,"aud":audience,"iat":now,"exp":now.saturating_add(120)}))
    }
    pub fn sign_claims(&self, claims: &Value) -> Result<String, HostError> {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg":"ES256","typ":"JWT","kid":self.kid}),
        )?);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header}.{claims}");
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(self.key.sign(signing_input.as_bytes()).to_bytes())
        ))
    }
}

/// Verify a PACT ES256 token against an explicitly trusted issuer/JWKS and
/// provider-assigned audience. Never fetch keys from an unverified token URL.
pub fn verify_identity(
    token: &str,
    jwks: &Value,
    issuer: &str,
    audience: &str,
    now: u64,
) -> Result<Value, HostError> {
    let claims = verify_jws(token, jwks)?;
    let iat = claims["iat"]
        .as_u64()
        .ok_or_else(|| invalid("missing iat"))?;
    let exp = claims["exp"]
        .as_u64()
        .ok_or_else(|| invalid("missing exp"))?;
    if claims["iss"] != issuer
        || claims["aud"] != audience
        || claims["sub"].as_str().is_none_or(str::is_empty)
        || iat > now.saturating_add(30)
        || exp <= iat
        || exp - iat > 300
        || exp.saturating_add(30) < now
    {
        return Err(invalid("invalid PACT identity claims"));
    }
    Ok(claims)
}

pub fn verify_jws(token: &str, jwks: &Value) -> Result<Value, HostError> {
    if token.len() > 64 * 1024 {
        return Err(invalid("oversized JWS"));
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid("invalid compact JWS"));
    }
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| invalid("invalid JWS encoding"))?,
    )?;
    if !matches!(header["alg"].as_str(), Some("ES256" | "RS256"))
        || header["kid"].as_str().is_none_or(str::is_empty)
        || header.get("crit").is_some()
        || header.get("b64").is_some()
    {
        return Err(invalid("unsupported JWS header"));
    }
    let key = jwks["keys"]
        .as_array()
        .and_then(|keys| {
            keys.iter().find(|key| {
                key["kid"] == header["kid"]
                    && key.get("alg").is_none_or(|alg| alg == &header["alg"])
                    && key.get("use").is_none_or(|usage| usage == "sig")
            })
        })
        .ok_or_else(|| invalid("untrusted JWS key"))?;
    let coordinate = |name: &str| -> Result<Vec<u8>, HostError> {
        URL_SAFE_NO_PAD
            .decode(
                key[name]
                    .as_str()
                    .ok_or_else(|| invalid("missing JWK coordinate"))?,
            )
            .map_err(|_| invalid("invalid JWK coordinate"))
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| invalid("invalid signature encoding"))?;
    let input = format!("{}.{}", parts[0], parts[1]);
    if header["alg"] == "ES256" {
        if key["kty"] != "EC" || key["crv"] != "P-256" {
            return Err(invalid("wrong key for ES256"));
        }
        let x = coordinate("x")?;
        let y = coordinate("y")?;
        if x.len() != 32 || y.len() != 32 {
            return Err(invalid("invalid P-256 coordinate length"));
        }
        let mut point = vec![4];
        point.extend(x);
        point.extend(y);
        let key = VerifyingKey::from_sec1_bytes(&point)
            .map_err(|_| invalid("invalid JWK curve point"))?;
        let signature =
            Signature::from_slice(&bytes).map_err(|_| invalid("invalid ES256 signature"))?;
        key.verify(input.as_bytes(), &signature)
            .map_err(|_| invalid("JWS signature did not verify"))?;
    } else {
        if key["kty"] != "RSA" {
            return Err(invalid("wrong key for RS256"));
        }
        let n = BigUint::from_bytes_be(&coordinate("n")?);
        if !(2048..=8192).contains(&n.bits()) {
            return Err(invalid("unsupported RSA modulus size"));
        }
        let key = RsaPublicKey::new(n, BigUint::from_bytes_be(&coordinate("e")?))
            .map_err(|_| invalid("invalid RSA key"))?;
        let signature = rsa::pkcs1v15::Signature::try_from(bytes.as_slice())
            .map_err(|_| invalid("invalid RS256 signature"))?;
        rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key)
            .verify(input.as_bytes(), &signature)
            .map_err(|_| invalid("JWS signature did not verify"))?;
    }
    Ok(serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| invalid("invalid claims encoding"))?,
    )?)
}

fn invalid(message: &str) -> HostError {
    HostError::Invalid(message.into())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn checked_url(value: &str) -> Result<Url, HostError> {
    let url = Url::parse(value).map_err(|_| invalid("invalid protocol URL"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (loopback && url.scheme() == "http"))
    {
        return Err(invalid(
            "protocol URLs require HTTPS (HTTP only on loopback fixtures)",
        ));
    }
    Ok(url)
}

pub struct PactClient {
    identity: Arc<PactIdentity>,
    subject: String,
    audience: String,
    http: Client,
}

pub struct PactPeer {
    pub card: Value,
    pub interface_url: String,
}

#[derive(Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}
fn default_interval() -> u64 {
    5
}

/// Sensitive provider-issued credential; deliberately has no Debug/Serialize.
#[derive(Deserialize)]
pub struct DelegationToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
    pub refresh_token: Option<String>,
}
impl DelegationToken {
    pub fn permits(&self, scope: &str) -> bool {
        self.scope
            .split_whitespace()
            .any(|allowed| allowed == scope)
    }
}

impl PactClient {
    pub fn new(
        identity: Arc<PactIdentity>,
        subject: String,
        audience: String,
    ) -> Result<Self, HostError> {
        identity.token(&subject, &audience, now())?;
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| invalid("could not build protocol client"))?;
        Ok(Self {
            identity,
            subject,
            audience,
            http,
        })
    }
    pub async fn discover(&self, card_url: &str) -> Result<PactPeer, HostError> {
        let mut url = checked_url(card_url)?;
        let mut redirects = 0;
        let card = loop {
            let response = self
                .http
                .get(url.clone())
                .send()
                .await
                .map_err(|_| invalid("agent card request failed"))?;
            if response.status().is_redirection() {
                redirects += 1;
                if redirects > 5 {
                    return Err(invalid("too many agent card redirects"));
                }
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| invalid("agent card redirect has no location"))?;
                url = checked_url(
                    url.join(location)
                        .map_err(|_| invalid("invalid card redirect"))?
                        .as_str(),
                )?;
                continue;
            }
            break read_response(response, false).await?;
        };
        let interface = card["supportedInterfaces"]
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|i| i["protocolBinding"] == "HTTP+JSON" && i["protocolVersion"] == "1.0")
            })
            .and_then(|i| i["url"].as_str())
            .ok_or_else(|| invalid("card has no A2A 1.0 HTTP+JSON interface"))?;
        let interface_url = checked_url(interface)?
            .to_string()
            .trim_end_matches('/')
            .to_string();
        Ok(PactPeer {
            card,
            interface_url,
        })
    }
    pub async fn send(
        &self,
        peer: &PactPeer,
        message_id: &str,
        text: &str,
        context_id: Option<&str>,
        delegation: Option<&DelegationToken>,
    ) -> Result<Value, HostError> {
        if message_id.is_empty() || text.trim().is_empty() {
            return Err(invalid("message id and nonblank text are required"));
        }
        let mut message =
            json!({"messageId":message_id,"role":"ROLE_USER","parts":[{"text":text}]});
        if let Some(context) = context_id {
            message["contextId"] = json!(context);
        }
        let mut request = self
            .http
            .post(checked_url(&format!(
                "{}/message:send",
                peer.interface_url
            ))?)
            .bearer_auth(self.identity.token(&self.subject, &self.audience, now())?)
            .header("A2A-Version", "1.0")
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&json!({"message":message}))?);
        if let Some(token) = delegation {
            request = request.header(
                "X-A2A-User-Delegation",
                format!("Bearer {}", token.access_token),
            );
        }
        read_response(
            request
                .send()
                .await
                .map_err(|_| invalid("A2A request failed"))?,
            true,
        )
        .await
    }
    pub async fn request_delegation(
        &self,
        peer: &PactPeer,
        scopes: &[String],
    ) -> Result<DeviceAuthorization, HostError> {
        let flow = delegation_flow(&peer.card)?;
        if scopes.is_empty()
            || scopes
                .iter()
                .any(|scope| flow["scopes"].get(scope).is_none())
        {
            return Err(invalid("requested scope is absent from the Brand card"));
        }
        let response = self
            .form(
                flow["deviceAuthorizationUrl"]
                    .as_str()
                    .ok_or_else(|| invalid("missing device authorization URL"))?,
                &[
                    ("client_id", self.identity.issuer.as_str()),
                    ("scope", &scopes.join(" ")),
                ],
            )
            .await?;
        let result: DeviceAuthorization = serde_json::from_value(response)?;
        checked_url(&result.verification_uri_complete)?;
        Ok(result)
    }
    /// The caller schedules polling at `interval`, applies RFC8628 slow_down,
    /// and presents the Brand URL directly to the person. No login proxying.
    pub async fn poll_delegation(
        &self,
        peer: &PactPeer,
        device_code: &str,
        requested_scopes: &[String],
    ) -> Result<DelegationToken, HostError> {
        let flow = delegation_flow(&peer.card)?;
        let response = self
            .form(
                flow["tokenUrl"]
                    .as_str()
                    .ok_or_else(|| invalid("missing token URL"))?,
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", self.identity.issuer.as_str()),
                ],
            )
            .await?;
        let token: DelegationToken = serde_json::from_value(response)?;
        if !token.token_type.eq_ignore_ascii_case("bearer")
            || token
                .scope
                .split_whitespace()
                .any(|scope| !requested_scopes.iter().any(|requested| requested == scope))
        {
            return Err(invalid("provider token exceeds requested consent scopes"));
        }
        Ok(token)
    }
    async fn form(&self, url: &str, fields: &[(&str, &str)]) -> Result<Value, HostError> {
        let mut encoded = Url::parse("https://form.invalid").unwrap();
        encoded
            .query_pairs_mut()
            .extend_pairs(fields.iter().copied());
        let response = self
            .http
            .post(checked_url(url)?)
            .bearer_auth(self.identity.token(&self.subject, &self.audience, now())?)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded.query().unwrap_or("").to_string())
            .send()
            .await
            .map_err(|_| invalid("delegation request failed"))?;
        read_response(response, false).await
    }
}

fn delegation_flow(card: &Value) -> Result<&Value, HostError> {
    card["securitySchemes"]
        .as_object()
        .and_then(|schemes| {
            schemes
                .values()
                .find_map(|scheme| scheme.pointer("/oauth2SecurityScheme/flows/deviceCode"))
        })
        .ok_or_else(|| invalid("Brand does not offer PACT delegated authority"))
}

async fn read_response(mut response: reqwest::Response, a2a: bool) -> Result<Value, HostError> {
    let status = response.status();
    let retry = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unspecified")
        .to_string();
    if status.as_u16() == 401 {
        return Err(HostError::Rejected(
            "PACT identity or delegation token rejected".into(),
        ));
    }
    if status.as_u16() == 429 {
        return Err(HostError::Rejected(format!(
            "PACT rate limited; Retry-After: {retry}"
        )));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if a2a && status.is_success() && !content_type.starts_with("application/a2a+json") {
        return Err(invalid("Provider did not return A2A content type"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > 4 * 1024 * 1024)
    {
        return Err(invalid("protocol response too large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("protocol response interrupted"))?
    {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(invalid("protocol response too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if !status.is_success() {
        // Read the A2A reason, not a guess derived from its HTTP status.
        let reason = value
            .pointer("/error/details/0/reason")
            .and_then(Value::as_str)
            .or_else(|| value["error"].as_str())
            .unwrap_or("unknown protocol error");
        return Err(HostError::Rejected(reason.into()));
    }
    Ok(value)
}

/// A delegated response is evidence only after its signed receipt matches the
/// expected grant, person, PA and Brand. The caller persists the returned claims
/// with its action receipt; credentials and an unverified receipt are not logged.
pub fn verify_receipt(
    reply: &Value,
    jwks: &Value,
    grant: &str,
    user: &str,
    pa: &str,
    brand: &str,
    allowed_scopes: &[String],
) -> Result<Value, HostError> {
    let receipt = reply
        .pointer("/message/metadata/pact.receipt")
        .or_else(|| reply.pointer("/task/metadata/pact.receipt"))
        .or_else(|| reply.pointer("/metadata/pact.receipt"))
        .ok_or_else(|| invalid("delegated response has no PACT receipt"))?;
    let claims = verify_jws(
        receipt["jws"]
            .as_str()
            .ok_or_else(|| invalid("missing signed receipt"))?,
        jwks,
    )?;
    if claims != receipt["claims"]
        || claims["grantId"] != grant
        || claims["user"] != user
        || claims["pa"] != pa
        || claims["brand"] != brand
        || claims["actions"].as_array().is_none()
        || claims.get("ts").is_none()
    {
        return Err(invalid("PACT receipt does not match the delegated action"));
    }
    let scopes = claims["scopesUsed"]
        .as_array()
        .ok_or_else(|| invalid("receipt has no scope list"))?;
    if scopes.iter().any(|scope| {
        scope
            .as_str()
            .is_none_or(|scope| !allowed_scopes.iter().any(|allowed| allowed == scope))
    }) {
        return Err(invalid("receipt claims an unconsented scope"));
    }
    Ok(claims)
}
