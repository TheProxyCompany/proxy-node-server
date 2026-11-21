//! Axum router and [`PullHandler`] contract for `POST /mesh/pull`.

use std::future::Future;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use super::pull_client::unix_ms;
use super::pull_server::{admit_pull_ack, build_pull_page, classify_pull_request_error};
use super::server::ServeState;
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::LogSource;
use crate::pull::{
    MAX_PULL_REQUEST_BYTES, PULL_PATH, PullPage, PullRequest, seal_pull_page, verify_pull_request,
};
use crate::registry::DeviceBook;

/// Server-side handler contract for [`PULL_PATH`] (`POST /mesh/pull`).
pub trait PullHandler: Clone + Send + Sync + 'static {
    fn identity(&self) -> &DeviceIdentity;

    fn now_ms(&self) -> i64 {
        unix_ms() as i64
    }

    fn response_hlc(&self) -> Hlc {
        Hlc((self.now_ms().max(0) as u64) << 16)
    }

    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, String>;

    fn is_peer_trusted(&self, _peer: &DeviceId) -> Result<bool, String> {
        Ok(true)
    }

    fn is_coverage_primed(&self) -> Result<bool, String> {
        Ok(true)
    }

    fn admit_pull_ack(
        &self,
        _peer: &DeviceId,
        _request: &PullRequest,
    ) -> impl Future<Output = Result<Option<PullPage>, String>> + Send {
        async { Ok(None) }
    }

    fn serve_pull(&self, peer: &DeviceId, request: PullRequest) -> Result<PullPage, String>;
}

/// Mount `POST /mesh/pull` ([`PULL_PATH`]) backed by `handler`.
pub fn pull_router<H: PullHandler>(handler: H) -> axum::Router {
    async fn post_pull<H: PullHandler>(
        State(handler): State<H>,
        body: axum::body::Bytes,
    ) -> Response {
        let now_ms = handler.now_ms();
        let mut lookup_error: Option<String> = None;
        let (peer, request) =
            match verify_pull_request(&body, now_ms, |id| match handler.lookup_peer_sec1(id) {
                Ok(key) => Ok(key),
                Err(error) => {
                    lookup_error = Some(error.clone());
                    Err(error)
                }
            }) {
                Ok(verified) => verified,
                Err(message) => {
                    if let Some(error) = lookup_error {
                        return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
                    }
                    return (classify_pull_request_error(&message), message).into_response();
                }
            };
        match handler.is_peer_trusted(&peer) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::FORBIDDEN,
                    "Pull requester is not a trusted device",
                )
                    .into_response();
            }
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
        match handler.is_coverage_primed() {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Origin coverage is still priming",
                )
                    .into_response();
            }
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
        let page = match handler.admit_pull_ack(&peer, &request).await {
            Ok(Some(reset)) => reset,
            Ok(None) => match handler.serve_pull(&peer, request) {
                Ok(page) => page,
                Err(message) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
                }
            },
            Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        };
        match seal_pull_page(&page, handler.identity(), handler.response_hlc()) {
            Ok(bytes) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response(),
            Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
    }

    axum::Router::new()
        .route(PULL_PATH, post(post_pull::<H>))
        .layer(DefaultBodyLimit::max(MAX_PULL_REQUEST_BYTES))
        .with_state(handler)
}

impl<L: LogSource, D: DeviceBook> PullHandler for ServeState<L, D> {
    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, String> {
        self.relay_callers.try_key_for_device(peer)
    }

    fn admit_pull_ack(
        &self,
        peer: &DeviceId,
        request: &PullRequest,
    ) -> impl Future<Output = Result<Option<PullPage>, String>> + Send {
        let result = admit_pull_ack(self, peer, request);
        async move { result }
    }

    fn serve_pull(&self, peer: &DeviceId, request: PullRequest) -> Result<PullPage, String> {
        build_pull_page(self, peer, &request)
    }
}
