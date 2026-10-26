//! Cryptographic signing, verification, and wire decoding for Relay v2 and
//! attested `/devices` responses.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use p256::ecdsa::{Signature, VerifyingKey};

use super::server::octet;
use super::{
    RELAY_PROTOCOL_VERSION, RelayCursorV2, RelayOpV2, RelayPageV2, RelayResponseV2,
    RelayWireEntryV2, decode_fixed_hex,
};
use crate::error::TransportError;
use crate::identity::{DeviceId, DeviceIdentity, encode_hex};
use crate::log::{RelayLogEntry, RelayStreamState};
use crate::op::SignedOp;
use crate::registry::DeviceBook;

pub(super) const RELAY_OPS_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/relay/ops/v2\0";
pub(super) const RELAY_HEAD_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/relay/head/v2\0";
pub(super) const RELAY_WATCH_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/relay/watch/v2\0";
pub(super) const RELAY_OPS_REQUEST_CONTEXT: &[u8] = b"proxy-node-server/relay/request/ops/v2\0";
pub(super) const RELAY_HEAD_REQUEST_CONTEXT: &[u8] = b"proxy-node-server/relay/request/head/v2\0";
pub(super) const RELAY_WATCH_REQUEST_CONTEXT: &[u8] = b"proxy-node-server/relay/request/watch/v2\0";
pub(super) const RELAY_NONCE_HEADER: &str = "x-proxy-relay-nonce";
pub(super) const RELAY_CALLER_HEADER: &str = "x-proxy-relay-caller";
pub(super) const RELAY_REQUEST_SIGNATURE_HEADER: &str = "x-proxy-relay-request-signature";
pub(super) const RELAY_SIGNATURE_HEADER: &str = "x-proxy-relay-signature";

pub(super) const RELAY_REPLAY_TTL: Duration = Duration::from_secs(5 * 60);
pub(super) const RELAY_REPLAY_LIMIT: usize = 4096;
pub(super) type RelayReplayCache = Mutex<HashMap<(DeviceId, [u8; 32]), Instant>>;

pub(super) const DEVICE_BOOK_SIGNING_CONTEXT: &[u8] = b"proxy-node-server/device-book/v2\0";
pub(super) const DEVICE_BOOK_NONCE_HEADER: &str = "x-proxy-device-book-nonce";
pub(super) const DEVICE_BOOK_SIGNATURE_HEADER: &str = "x-proxy-device-book-signature";

#[derive(Clone, Copy)]
pub(super) struct RelayRequestAuth {
    pub(super) epoch: [u8; 32],
    pub(super) nonce: [u8; 32],
    pub(super) caller: DeviceId,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn relay_request<D: DeviceBook>(
    epoch: &str,
    after: u64,
    request_bound: u64,
    headers: &HeaderMap,
    request_context: &[u8],
    serving_peer: DeviceId,
    devices: &D,
    replays: &RelayReplayCache,
) -> Result<RelayRequestAuth, StatusCode> {
    let epoch = decode_fixed_hex::<32>(epoch).ok_or(StatusCode::BAD_REQUEST)?;
    if epoch == [0u8; 32] && after != 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let nonce = headers
        .get(RELAY_NONCE_HEADER)
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .ok()
        .and_then(decode_fixed_hex::<32>)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let caller = headers
        .get(RELAY_CALLER_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(decode_fixed_hex::<32>)
        .map(DeviceId::from_bytes)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let signature = headers
        .get(RELAY_REQUEST_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(decode_fixed_hex::<64>)
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if signature.normalize_s().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let sec1 = devices
        .try_key_for_device(&caller)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if DeviceIdentity::device_id_from_sec1(&sec1).ok() != Some(caller) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let verifying = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| StatusCode::UNAUTHORIZED)?;
    DeviceIdentity::verify(
        &verifying,
        &relay_request_signing_input(
            request_context,
            &caller,
            &serving_peer,
            &epoch,
            after,
            request_bound,
            &nonce,
        ),
        &signature,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let now = Instant::now();
    let mut replays = replays.lock().expect("relay replay cache mutex poisoned");
    replays.retain(|_, seen| now.saturating_duration_since(*seen) <= RELAY_REPLAY_TTL);
    if replays.contains_key(&(caller, nonce)) {
        return Err(StatusCode::CONFLICT);
    }
    if replays.len() >= RELAY_REPLAY_LIMIT {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    replays.insert((caller, nonce), now);
    Ok(RelayRequestAuth {
        epoch,
        nonce,
        caller,
    })
}

pub(super) fn relay_needs_reset(
    request_epoch: [u8; 32],
    after: u64,
    state: RelayStreamState,
) -> bool {
    (request_epoch == [0u8; 32] && state.floor > 0)
        || (request_epoch != [0u8; 32] && request_epoch != state.epoch)
        || (request_epoch == state.epoch && (after < state.floor || after > state.head))
}

pub(super) fn valid_relay_state(state: RelayStreamState) -> bool {
    state.epoch != [0u8; 32] && state.floor <= state.head
}

fn relay_request_signing_input(
    context: &[u8],
    caller: &DeviceId,
    serving_peer: &DeviceId,
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        context.len()
            + caller.as_bytes().len()
            + serving_peer.as_bytes().len()
            + request_epoch.len()
            + 8
            + 8
            + nonce.len(),
    );
    input.extend_from_slice(context);
    input.extend_from_slice(caller.as_bytes());
    input.extend_from_slice(serving_peer.as_bytes());
    input.extend_from_slice(request_epoch);
    input.extend_from_slice(&after.to_be_bytes());
    input.extend_from_slice(&request_bound.to_be_bytes());
    input.extend_from_slice(nonce);
    input
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sign_relay_request(
    identity: &DeviceIdentity,
    context: &[u8],
    serving_peer: &DeviceId,
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
) -> [u8; 64] {
    let signature = identity.sign(&relay_request_signing_input(
        context,
        &identity.device_id(),
        serving_peer,
        request_epoch,
        after,
        request_bound,
        nonce,
    ));
    let signature = signature.normalize_s().unwrap_or(signature).to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&signature);
    out
}

#[allow(clippy::too_many_arguments)]
fn relay_response_signing_input(
    context: &[u8],
    signer: &DeviceId,
    caller: &DeviceId,
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        context.len()
            + signer.as_bytes().len()
            + caller.as_bytes().len()
            + request_epoch.len()
            + 8
            + 8
            + nonce.len()
            + body.len(),
    );
    input.extend_from_slice(context);
    input.extend_from_slice(signer.as_bytes());
    input.extend_from_slice(caller.as_bytes());
    input.extend_from_slice(request_epoch);
    input.extend_from_slice(&after.to_be_bytes());
    input.extend_from_slice(&request_bound.to_be_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(body);
    input
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sign_relay_response(
    identity: &DeviceIdentity,
    caller: &DeviceId,
    context: &[u8],
    request_epoch: &[u8; 32],
    after: u64,
    request_bound: u64,
    nonce: &[u8; 32],
    body: &[u8],
) -> [u8; 64] {
    let signature = identity.sign(&relay_response_signing_input(
        context,
        &identity.device_id(),
        caller,
        request_epoch,
        after,
        request_bound,
        nonce,
        body,
    ));
    let signature = signature.normalize_s().unwrap_or(signature).to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&signature);
    out
}

#[allow(clippy::too_many_arguments)]
pub(super) fn signed_relay_response(
    identity: &DeviceIdentity,
    caller: DeviceId,
    context: &[u8],
    request_epoch: [u8; 32],
    after: u64,
    request_bound: u64,
    nonce: [u8; 32],
    state: RelayStreamState,
    reset: bool,
    next: u64,
    entries: Vec<RelayLogEntry>,
) -> Response {
    let mut wire_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let envelope = match entry.op.to_bytes() {
            Ok(envelope) => envelope,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        wire_entries.push(RelayWireEntryV2 {
            seq: entry.seq,
            envelope,
        });
    }
    let response = RelayResponseV2 {
        v: RELAY_PROTOCOL_VERSION,
        epoch: state.epoch,
        head: state.head,
        floor: state.floor,
        next,
        reset,
        entries: wire_entries,
    };
    let body = match postcard::to_allocvec(&response) {
        Ok(body) => body,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let signature = sign_relay_response(
        identity,
        &caller,
        context,
        &request_epoch,
        after,
        request_bound,
        &nonce,
        &body,
    );
    let Ok(signature) = HeaderValue::from_str(&encode_hex(&signature)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut http = octet(body);
    http.headers_mut()
        .insert(HeaderName::from_static(RELAY_SIGNATURE_HEADER), signature);
    http
}

fn device_book_signing_input(signer: &DeviceId, nonce: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        DEVICE_BOOK_SIGNING_CONTEXT.len() + signer.as_bytes().len() + nonce.len() + body.len(),
    );
    input.extend_from_slice(DEVICE_BOOK_SIGNING_CONTEXT);
    input.extend_from_slice(signer.as_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(body);
    input
}

pub(super) fn sign_device_book(
    identity: &DeviceIdentity,
    nonce: &[u8; 32],
    body: &[u8],
) -> [u8; 64] {
    let signature = identity.sign(&device_book_signing_input(
        &identity.device_id(),
        nonce,
        body,
    ));
    let signature = signature.normalize_s().unwrap_or(signature);
    let bytes = signature.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

pub(super) fn verify_device_book(
    expected_peer: DeviceId,
    expected_sec1: &[u8; 33],
    nonce: &[u8; 32],
    body: &[u8],
    signature_hex: &str,
) -> Result<(), TransportError> {
    let derived = DeviceIdentity::device_id_from_sec1(expected_sec1)?;
    if derived != expected_peer {
        return Err(TransportError::IdentityMismatch {
            advertised: expected_peer.to_hex(),
            derived: derived.to_hex(),
        });
    }
    let verifying = VerifyingKey::from_sec1_bytes(expected_sec1)
        .map_err(|_| crate::error::IdentityError::InvalidPublicKey)?;
    let signature_bytes = decode_fixed_hex::<64>(signature_hex)
        .ok_or_else(|| TransportError::Wire("invalid device-book signature header".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| TransportError::Wire("invalid device-book P-256 signature".into()))?;
    if signature.normalize_s().is_some() {
        return Err(TransportError::Wire(
            "device-book signature is not low-S canonical".into(),
        ));
    }
    DeviceIdentity::verify(
        &verifying,
        &device_book_signing_input(&expected_peer, nonce, body),
        &signature,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_relay_signature(
    caller: DeviceId,
    expected_peer: DeviceId,
    expected_sec1: &[u8; 33],
    context: &[u8],
    cursor: RelayCursorV2,
    request_bound: u64,
    nonce: &[u8; 32],
    body: &[u8],
    signature_hex: &str,
) -> Result<(), TransportError> {
    let derived = DeviceIdentity::device_id_from_sec1(expected_sec1)?;
    if derived != expected_peer {
        return Err(TransportError::IdentityMismatch {
            advertised: expected_peer.to_hex(),
            derived: derived.to_hex(),
        });
    }
    let verifying = VerifyingKey::from_sec1_bytes(expected_sec1)
        .map_err(|_| crate::error::IdentityError::InvalidPublicKey)?;
    let signature_bytes = decode_fixed_hex::<64>(signature_hex)
        .ok_or_else(|| TransportError::Wire("invalid relay signature header".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| TransportError::Wire("invalid relay P-256 signature".into()))?;
    if signature.normalize_s().is_some() {
        return Err(TransportError::Wire(
            "relay signature is not low-S canonical".into(),
        ));
    }
    DeviceIdentity::verify(
        &verifying,
        &relay_response_signing_input(
            context,
            &expected_peer,
            &caller,
            &cursor.epoch,
            cursor.after,
            request_bound,
            nonce,
            body,
        ),
        &signature,
    )?;
    Ok(())
}

pub(super) fn decode_relay_response(
    wire: RelayResponseV2,
    cursor: RelayCursorV2,
    max_entries: usize,
    status_only: bool,
) -> Result<RelayPageV2, TransportError> {
    if wire.v != RELAY_PROTOCOL_VERSION {
        return Err(TransportError::Wire(format!(
            "unsupported relay protocol version {}",
            wire.v
        )));
    }
    if wire.epoch == [0u8; 32] || wire.floor > wire.head {
        return Err(TransportError::Wire("invalid relay stream bounds".into()));
    }
    let cursor_invalid = (cursor.epoch == [0u8; 32] && wire.floor > 0)
        || (cursor.epoch != [0u8; 32] && cursor.epoch != wire.epoch)
        || (cursor.epoch == wire.epoch && (cursor.after < wire.floor || cursor.after > wire.head));
    if wire.reset {
        if !cursor_invalid || !wire.entries.is_empty() || wire.next != wire.floor {
            return Err(TransportError::Wire("invalid relay reset response".into()));
        }
        return Ok(RelayPageV2 {
            epoch: wire.epoch,
            head: wire.head,
            floor: wire.floor,
            next: wire.next,
            reset: true,
            entries: Vec::new(),
        });
    }
    if cursor_invalid {
        return Err(TransportError::Wire(
            "relay response did not reset an invalid cursor".into(),
        ));
    }
    if status_only {
        if !wire.entries.is_empty() || wire.next != cursor.after {
            return Err(TransportError::Wire("invalid relay status response".into()));
        }
    } else {
        if wire.entries.len() > max_entries {
            return Err(TransportError::Wire(
                "relay page exceeds requested limit".into(),
            ));
        }
        let mut previous = cursor.after;
        for entry in &wire.entries {
            if previous.checked_add(1) != Some(entry.seq) || entry.seq > wire.head {
                return Err(TransportError::Wire(
                    "relay sequence is not strictly increasing as a contiguous prefix".into(),
                ));
            }
            previous = entry.seq;
        }
        let expected_next = wire
            .entries
            .last()
            .map(|entry| entry.seq)
            .unwrap_or(cursor.after);
        if wire.next != expected_next || wire.next < wire.floor || wire.next > wire.head {
            return Err(TransportError::Wire(
                "invalid relay page next cursor".into(),
            ));
        }
    }

    let mut entries = Vec::with_capacity(wire.entries.len());
    for entry in wire.entries {
        entries.push(RelayOpV2 {
            seq: entry.seq,
            op: SignedOp::from_bytes(&entry.envelope)?,
        });
    }
    Ok(RelayPageV2 {
        epoch: wire.epoch,
        head: wire.head,
        floor: wire.floor,
        next: wire.next,
        reset: false,
        entries,
    })
}
