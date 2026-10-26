//! HTTP pull client ([`HttpPullSource`]) for v1 semantic pull, Relay v2, and
//! Pull v3.

use std::time::Duration;

use axum::http::StatusCode;
use rand_core::{OsRng, RngCore};

use super::relay::{
    DEVICE_BOOK_NONCE_HEADER, DEVICE_BOOK_SIGNATURE_HEADER, RELAY_CALLER_HEADER,
    RELAY_HEAD_REQUEST_CONTEXT, RELAY_HEAD_SIGNING_CONTEXT, RELAY_NONCE_HEADER,
    RELAY_OPS_REQUEST_CONTEXT, RELAY_OPS_SIGNING_CONTEXT, RELAY_REQUEST_SIGNATURE_HEADER,
    RELAY_SIGNATURE_HEADER, RELAY_WATCH_REQUEST_CONTEXT, RELAY_WATCH_SIGNING_CONTEXT,
    decode_relay_response, sign_relay_request, verify_device_book, verify_relay_signature,
};
use super::{
    DEFAULT_PULL_LIMIT, DEFAULT_REQUEST_TIMEOUT, DevicesResp, IdentityResp, PullResponse,
    RelayCursorV2, RelayPageV2, RelayResponseV2, WATCH_MAX_WAIT, encode_order_key,
};
use crate::error::TransportError;
use crate::identity::{DeviceId, DeviceIdentity, encode_hex};
use crate::op::{OrderKey, SignedOp};
use crate::pull_v3::{MAX_V3_RESPONSE_BYTES, PULL_PATH};
use crate::transport::{Cursor, PullSource};

/// Pulls a peer's op-log over HTTP.
pub struct HttpPullSource {
    pub(super) base_url: String,
    pub(super) client: reqwest::Client,
    limit: u16,
}

impl HttpPullSource {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            client: build_client(DEFAULT_REQUEST_TIMEOUT),
            limit: DEFAULT_PULL_LIMIT,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn with_limit(mut self, limit: u16) -> Self {
        self.limit = limit;
        self
    }

    /// Override the per-request timeout (default [`DEFAULT_REQUEST_TIMEOUT`]).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = build_client(timeout);
        self
    }

    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, TransportError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!("status {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TransportError::Http(e.to_string()))
    }

    /// Fetch the peer's device id and verifying key.
    pub async fn fetch_identity(&self) -> Result<IdentityResp, TransportError> {
        let bytes = self
            .get_bytes(&format!("{}/identity", self.base_url))
            .await?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))
    }

    /// Fetch the peer's current log head, for liveness/debug.
    pub async fn fetch_head(&self) -> Result<OrderKey, TransportError> {
        let bytes = self.get_bytes(&format!("{}/head", self.base_url)).await?;
        let arr: [u8; 72] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::Wire("head is not 72 bytes".into()))?;
        Ok(OrderKey::from_wire(&arr))
    }

    /// Long-poll the peer's `/watch`.
    pub async fn watch_head(
        &self,
        known: OrderKey,
        wait: Duration,
    ) -> Result<OrderKey, TransportError> {
        let url = format!(
            "{}/watch?head={}&wait={}",
            self.base_url,
            encode_order_key(&known),
            wait.as_millis()
        );
        let resp = self
            .client
            .get(&url)
            .timeout(wait + DEFAULT_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!("status {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let arr: [u8; 72] = bytes[..]
            .try_into()
            .map_err(|_| TransportError::Wire("watch head is not 72 bytes".into()))?;
        Ok(OrderKey::from_wire(&arr))
    }

    /// Fetch the peer's trusted device set (transitive key gossip).
    pub async fn fetch_devices(&self) -> Result<DevicesResp, TransportError> {
        let bytes = self
            .get_bytes(&format!("{}/devices", self.base_url))
            .await?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))
    }

    /// Fetch `/devices` and authenticate its exact response bytes with the
    /// already-pinned peer identity before deserializing them.
    pub async fn fetch_attested_devices(
        &self,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
    ) -> Result<DevicesResp, TransportError> {
        let mut nonce = [0u8; 32];
        OsRng.try_fill_bytes(&mut nonce).map_err(|e| {
            TransportError::Http(format!("device-book nonce generation failed: {e}"))
        })?;
        let resp = self
            .client
            .get(format!("{}/devices", self.base_url))
            .header(DEVICE_BOOK_NONCE_HEADER, encode_hex(&nonce))
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!("status {}", resp.status())));
        }
        let signature = resp
            .headers()
            .get(DEVICE_BOOK_SIGNATURE_HEADER)
            .ok_or_else(|| {
                TransportError::Wire(format!(
                    "missing {DEVICE_BOOK_SIGNATURE_HEADER} response header"
                ))
            })?
            .to_str()
            .map_err(|_| {
                TransportError::Wire(format!(
                    "invalid {DEVICE_BOOK_SIGNATURE_HEADER} response header"
                ))
            })?
            .to_owned();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        verify_device_book(
            expected_peer,
            expected_public_key_sec1,
            &nonce,
            &bytes,
            &signature,
        )?;
        postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_relay_v2(
        &self,
        local_identity: &DeviceIdentity,
        url: String,
        context: &[u8],
        request_context: &[u8],
        request_bound: u64,
        cursor: RelayCursorV2,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        max_entries: usize,
        status_only: bool,
        timeout: Option<Duration>,
    ) -> Result<RelayPageV2, TransportError> {
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| TransportError::Http(format!("relay nonce generation failed: {e}")))?;
        let request_signature = sign_relay_request(
            local_identity,
            request_context,
            &expected_peer,
            &cursor.epoch,
            cursor.after,
            request_bound,
            &nonce,
        );
        let mut request = self
            .client
            .get(url)
            .header(RELAY_NONCE_HEADER, encode_hex(&nonce))
            .header(RELAY_CALLER_HEADER, local_identity.device_id().to_hex())
            .header(
                RELAY_REQUEST_SIGNATURE_HEADER,
                encode_hex(&request_signature),
            );
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED
        ) {
            return Err(TransportError::RelayV2Unsupported {
                status: response.status().as_u16(),
            });
        }
        if !response.status().is_success() {
            return Err(TransportError::Http(format!(
                "status {}",
                response.status()
            )));
        }
        let signature = response
            .headers()
            .get(RELAY_SIGNATURE_HEADER)
            .ok_or_else(|| {
                TransportError::Wire(format!("missing {RELAY_SIGNATURE_HEADER} response header"))
            })?
            .to_str()
            .map_err(|_| {
                TransportError::Wire(format!("invalid {RELAY_SIGNATURE_HEADER} response header"))
            })?
            .to_owned();
        let body = response
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        verify_relay_signature(
            local_identity.device_id(),
            expected_peer,
            expected_public_key_sec1,
            context,
            cursor,
            request_bound,
            &nonce,
            &body,
            &signature,
        )?;
        let wire: RelayResponseV2 =
            postcard::from_bytes(&body).map_err(|e| TransportError::Wire(e.to_string()))?;
        decode_relay_response(wire, cursor, max_entries, status_only)
    }

    /// Pull a bounded, authenticated page from the peer's insertion-ordered v2
    /// relay stream.
    pub async fn fetch_relay_ops_v2(
        &self,
        local_identity: &DeviceIdentity,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        cursor: RelayCursorV2,
    ) -> Result<RelayPageV2, TransportError> {
        let url = format!(
            "{}/v2/ops?epoch={}&after={}&limit={}",
            self.base_url,
            encode_hex(&cursor.epoch),
            cursor.after,
            self.limit
        );
        self.request_relay_v2(
            local_identity,
            url,
            RELAY_OPS_SIGNING_CONTEXT,
            RELAY_OPS_REQUEST_CONTEXT,
            self.limit as u64,
            cursor,
            expected_peer,
            expected_public_key_sec1,
            self.limit as usize,
            false,
            None,
        )
        .await
    }

    /// Fetch authenticated relay stream bounds without transferring entries.
    pub async fn fetch_relay_head_v2(
        &self,
        local_identity: &DeviceIdentity,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        cursor: RelayCursorV2,
    ) -> Result<RelayPageV2, TransportError> {
        let url = format!(
            "{}/v2/head?epoch={}&after={}",
            self.base_url,
            encode_hex(&cursor.epoch),
            cursor.after
        );
        self.request_relay_v2(
            local_identity,
            url,
            RELAY_HEAD_SIGNING_CONTEXT,
            RELAY_HEAD_REQUEST_CONTEXT,
            0,
            cursor,
            expected_peer,
            expected_public_key_sec1,
            0,
            true,
            None,
        )
        .await
    }

    /// Long-poll authenticated relay bounds, waking for every unique insertion
    /// even when its semantic [`OrderKey`] is below the existing v1 head.
    pub async fn watch_relay_head_v2(
        &self,
        local_identity: &DeviceIdentity,
        expected_peer: DeviceId,
        expected_public_key_sec1: &[u8; 33],
        cursor: RelayCursorV2,
        wait: Duration,
    ) -> Result<RelayPageV2, TransportError> {
        let wait = wait.min(WATCH_MAX_WAIT);
        let wait_millis = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let url = format!(
            "{}/v2/watch?epoch={}&after={}&wait={}",
            self.base_url,
            encode_hex(&cursor.epoch),
            cursor.after,
            wait_millis
        );
        self.request_relay_v2(
            local_identity,
            url,
            RELAY_WATCH_SIGNING_CONTEXT,
            RELAY_WATCH_REQUEST_CONTEXT,
            wait_millis,
            cursor,
            expected_peer,
            expected_public_key_sec1,
            0,
            true,
            Some(wait + DEFAULT_REQUEST_TIMEOUT),
        )
        .await
    }

    /// POST a signed v3 pull request envelope to [`PULL_PATH`] and return
    /// `(status_code, raw_response_bytes)`, bounded by [`MAX_V3_RESPONSE_BYTES`].
    pub async fn pull_v3_bytes(
        &self,
        signed_request: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), TransportError> {
        let url = format!("{}{PULL_PATH}", self.base_url);
        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .timeout(Duration::from_secs(60))
            .body(signed_request)
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_V3_RESPONSE_BYTES as u64)
        {
            return Err(TransportError::Wire("oversized v3 pull page".into()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if bytes.len() > MAX_V3_RESPONSE_BYTES {
            return Err(TransportError::Wire("oversized v3 pull page".into()));
        }
        Ok((status, bytes.to_vec()))
    }
}

fn build_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client build")
}

impl PullSource for HttpPullSource {
    type Error = TransportError;

    async fn pull(&self, since: Cursor) -> Result<Vec<SignedOp>, Self::Error> {
        let url = format!(
            "{}/ops?since={}&limit={}",
            self.base_url,
            encode_order_key(&since),
            self.limit
        );
        let bytes = self.get_bytes(&url).await?;
        let resp: PullResponse =
            postcard::from_bytes(&bytes).map_err(|e| TransportError::Wire(e.to_string()))?;
        let mut ops = Vec::with_capacity(resp.ops.len());
        for raw in &resp.ops {
            ops.push(SignedOp::from_bytes(raw)?);
        }
        Ok(ops)
    }
}
