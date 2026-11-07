//! Internet-facing `<name>.proxy.ing` tunnel admission gate, device-dispatch
//! signature verification (`proxy.ing-device-request-v2`), path-family OAuth
//! scope enforcement, and localhost/loopback origin guards.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::identity::{DeviceId, DeviceIdentity};
use crate::oauth::ask_proof::PartyScope;

pub const DEVICE_REQUEST_PAYLOAD_VERSION: &str = "proxy.ing-device-request-v2";
pub const CF_CONNECTING_IP_HEADER: &str = "cf-connecting-ip";
pub const DEVICE_TIMESTAMP_HEADER: &str = "x-proxy-device-timestamp";
pub const DEVICE_SIGNATURE_HEADER: &str = "x-proxy-device-signature";
pub const DEVICE_REQUEST_MAX_SKEW_SECONDS: u64 = 300;
pub const MAX_DEVICE_DISPATCH_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const PARTY_BEARER_METADATA_KEY: &str = "party_bearer";
pub const EDGE_MAIL_DELIVERY_HEADER: &str = "x-proxy-edge-mail-delivery";
pub const RESOLVE_IN_PROXY: &str = "This Move can only be made from Proxy. A client on the address holds a bearer, not this Mac's trusted device key. Open the Move in Proxy and decide there.";

pub const DEVICE_CLAIM_HEADERS: &[&str] = &[
    "x-proxy-device-id",
    DEVICE_TIMESTAMP_HEADER,
    DEVICE_SIGNATURE_HEADER,
    "x-proxy-device-auth-version",
    "x-proxy-device-body-sha256",
    "x-proxy-authenticated-device",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestDeviceId(pub DeviceId);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelPrincipal {
    Account,
    OAuth { scope: Option<String> },
}

#[derive(Clone, Debug)]
pub struct PartyBearer {
    pub token_id: String,
    pub scope: PartyScope,
    pub signed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressCaller {
    pub owner_proven: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PartyRoute {
    OpenThread,
    Thread(String),
    Avatar(String),
    Nothing,
}

pub fn canonical_payload(
    username: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body_sha256: &str,
) -> String {
    format!(
        "{DEVICE_REQUEST_PAYLOAD_VERSION}\nusername={username}\nmethod={method}\npath={path}\ntimestamp={timestamp}\nbody_sha256={body_sha256}"
    )
}

pub fn sign_device_request(
    identity: &DeviceIdentity,
    username: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
) -> (String, String) {
    let body_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    let payload = canonical_payload(username, method, path, timestamp, &body_sha256);
    let sig = identity.sign(payload.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    (body_sha256, sig_b64)
}

pub fn agent_of_avatar_path(path: &str) -> Option<&str> {
    let agent = path
        .strip_prefix("/client/v1/agents/")?
        .strip_suffix("/avatar")?;
    (!agent.is_empty() && !agent.contains('/')).then_some(agent)
}

pub fn is_inference_path(path: &str) -> bool {
    path == "/inference" || path.starts_with("/inference/")
}

pub fn is_public_pages_request(method: &Method, path: &str) -> bool {
    (method == Method::GET || method == Method::HEAD)
        && (path == "/v1/public-profile"
            || path == "/client/v1/public-profile"
            || ["/client/p", "/p", "/inbox", "/client/inbox"]
                .iter()
                .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/"))))
}

pub fn is_edge_mail_inbound_request(method: &Method, path: &str, headers: &HeaderMap) -> bool {
    *method == Method::POST
        && (path == "/client/v1/proxy-ing/mail/inbound" || path == "/v1/mail/inbound")
        && header_str(headers, EDGE_MAIL_DELIVERY_HEADER) == Some("1")
}

pub fn family_of(method: &Method, path: &str) -> Option<&'static str> {
    let under = |prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    if under("/client/v1/proxy-ing/mail") || under("/v1/mail") {
        return Some("mail");
    }
    if under("/client/v1/threads") || under("/client/v1/content") {
        return Some("threads");
    }
    if *method == Method::GET {
        if let Some(rest) = path.strip_prefix("/client/v1/agents") {
            if rest.is_empty() || (rest.starts_with('/') && !rest[1..].contains('/')) {
                return Some("threads");
            }
            if agent_of_avatar_path(path).is_some() {
                return Some("threads");
            }
        }
        if under("/client/v1/map") || path == "/client/v1/graph/map" || under("/client/v1/timeline")
        {
            return Some("life-map-read");
        }
        if path == "/client/v1/moves" {
            return Some("moves");
        }
    }
    if *method == Method::POST && path == "/client/v1/map/mutations/score" {
        return Some("life-map-read");
    }
    if (under("/client/v1/map/nodes")
        || under("/client/v1/map/edges")
        || under("/client/v1/graph/nodes"))
        && matches!(*method, Method::PATCH | Method::POST)
    {
        return Some("life-map-write");
    }
    if *method == Method::POST
        && path
            .strip_prefix("/client/v1/moves/")
            .is_some_and(|rest| rest.ends_with("/resolve") && rest.matches('/').count() == 1)
    {
        return Some("moves");
    }
    if under("/mcp/proxy") {
        return Some("life-map-write");
    }
    if under("/mcp/computer") || under("/mcp/phone") {
        return Some("computer");
    }
    if under("/mcp/mail") {
        return Some("mail");
    }
    if under("/mcp/messages") {
        return Some("messages");
    }
    if is_inference_path(path) {
        return Some("inference");
    }
    None
}

pub fn party_route(method: &Method, path: &str) -> PartyRoute {
    if *method == Method::GET {
        if let Some(agent) = agent_of_avatar_path(path) {
            return PartyRoute::Avatar(agent.to_string());
        }
    }
    let Some(rest) = path.strip_prefix("/client/v1/threads") else {
        return PartyRoute::Nothing;
    };
    if rest.is_empty() || rest == "/" {
        return if *method == Method::POST {
            PartyRoute::OpenThread
        } else {
            PartyRoute::Nothing
        };
    }
    let Some(rest) = rest.strip_prefix('/') else {
        return PartyRoute::Nothing;
    };
    let mut parts = rest.splitn(2, '/');
    let id = parts.next().unwrap_or("").to_string();
    let tail = parts.next().unwrap_or("");
    if id.is_empty() {
        return PartyRoute::Nothing;
    }
    let allowed = match tail {
        "" | "queue-idle" | "events" => *method == Method::GET,
        "messages" => *method == Method::GET || *method == Method::POST,
        _ => false,
    };
    if allowed {
        PartyRoute::Thread(id)
    } else {
        PartyRoute::Nothing
    }
}

pub fn parse_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn decode_signature(header: &str) -> Option<Signature> {
    let bytes = URL_SAFE_NO_PAD.decode(header).ok()?;
    Signature::from_slice(&bytes).ok()
}

pub enum DeviceDispatchVerify {
    VerifiedMeshId(String),
    OwnerPhone,
    Rejected,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_device_dispatch_bytes(
    username: &str,
    local_registry_id: Option<&str>,
    method: &str,
    uri_path: &str,
    timestamp: &str,
    signature: &Signature,
    body_bytes: &[u8],
    trusted_mesh_keys: &[VerifyingKey],
    owner_phone_keys: &[VerifyingKey],
) -> DeviceDispatchVerify {
    let Ok(issued) = timestamp.parse::<u64>() else {
        return DeviceDispatchVerify::Rejected;
    };
    let Some(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
    else {
        return DeviceDispatchVerify::Rejected;
    };
    if now.abs_diff(issued) > DEVICE_REQUEST_MAX_SKEW_SECONDS {
        return DeviceDispatchVerify::Rejected;
    }
    let body_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(body_bytes));
    let signed_paths = local_registry_id
        .into_iter()
        .map(|registry_id| format!("/devices/{registry_id}{uri_path}"))
        .chain(std::iter::once(uri_path.to_string()))
        .collect::<Vec<_>>();
    let payloads = signed_paths
        .iter()
        .map(|path| canonical_payload(username, method, path, timestamp, &body_sha256))
        .collect::<Vec<_>>();

    if let Some(mesh_id) = trusted_mesh_keys
        .iter()
        .find(|key| {
            payloads
                .iter()
                .any(|payload| DeviceIdentity::verify(key, payload.as_bytes(), signature).is_ok())
        })
        .map(|key| DeviceIdentity::device_id_of_key(key).to_hex())
    {
        return DeviceDispatchVerify::VerifiedMeshId(mesh_id);
    }

    if owner_phone_keys.iter().any(|key| {
        payloads
            .iter()
            .any(|payload| DeviceIdentity::verify(key, payload.as_bytes(), signature).is_ok())
    }) {
        return DeviceDispatchVerify::OwnerPhone;
    }

    DeviceDispatchVerify::Rejected
}

pub fn apply_verified_mesh_header(headers: &mut HeaderMap, mesh_id: &str) {
    if let Ok(value) = HeaderValue::from_str(mesh_id) {
        headers.insert("x-proxy-device-id", value);
    }
}

pub fn is_allowed_browser_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let Some((host, port)) = rest.split_once(':') else {
        return false;
    };
    if host != "localhost" && host != "127.0.0.1" {
        return false;
    }
    !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit())
}

pub fn normalize_token(token: Option<String>) -> Option<String> {
    token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
}

pub async fn enforce_loopback_peer(req: Request<Body>, next: Next) -> Response {
    let loopback = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|peer| peer.0.ip().is_loopback());
    if !loopback {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

pub async fn enforce_localhost_origin(req: Request<Body>, next: Next) -> Response {
    if req
        .headers()
        .get(header::ORIGIN)
        .is_some_and(|origin| !origin.to_str().is_ok_and(is_allowed_browser_origin))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}
