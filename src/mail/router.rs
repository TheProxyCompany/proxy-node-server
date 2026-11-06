//! Axum HTTP router and inspectable webmail surface for `<username>@proxy.ing`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::json;

use super::{
    InboundEmailPayload, MailDraft, MailError, MailMessagePatch, MailStore, SendEmailRequest,
    build_raw_rfc5322, humanize_slug, store::random_hex_id,
};
use crate::address_web::escape_html;

const WEBMAIL_HTML: &str = include_str!("webmail.html");

/// Pluggable async outbound email dispatcher (e.g., forwarding signed RFC-5322
/// MIME payloads to the `.proxy.ing` Cloudflare Email Worker `/v1/mail/send`).
#[async_trait::async_trait]
pub trait OutboundMailer: Send + Sync + 'static {
    async fn send_raw_mime(
        &self,
        from: &str,
        to: &[String],
        raw_rfc5322: &str,
        req: &SendEmailRequest,
    ) -> Result<(), MailError>;
}

#[derive(Clone)]
struct MailRouterState {
    store: Arc<dyn MailStore>,
    mailer: Option<Arc<dyn OutboundMailer>>,
}

#[derive(Debug, Default, Deserialize)]
struct ListMessagesQuery {
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    unread_only: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Build the JSON API router for a `<username>@proxy.ing` mailbox.
///
/// Mount under `/client/v1/proxy-ing/mail` and `/v1/mail`.
pub fn mail_router(store: Arc<dyn MailStore>, mailer: Option<Arc<dyn OutboundMailer>>) -> Router {
    let state = MailRouterState { store, mailer };
    Router::new()
        .route("/account", get(get_account))
        .route("/folders", get(get_folders))
        .route("/messages", get(list_messages))
        .route(
            "/messages/{id}",
            get(get_message).post(patch_message).patch(patch_message),
        )
        .route("/inbound", post(post_inbound))
        .route("/drafts", get(list_drafts).post(save_draft))
        .route("/drafts/{id}", delete(delete_draft))
        .route("/send", post(post_send))
        .with_state(state)
}

/// Build the inspectable open-source HTML webmail router serving
/// `src/mail/webmail.html` at `/`, `/inbox`, `/client/inbox`, `/p/_mail`, and
/// `/client/p/_mail`.
pub fn webmail_router(store: Arc<dyn MailStore>) -> Router {
    Router::new()
        .route("/", get(render_webmail))
        .route("/inbox", get(render_webmail))
        .route("/client/inbox", get(render_webmail))
        .route("/p/_mail", get(render_webmail))
        .route("/client/p/_mail", get(render_webmail))
        .with_state(store)
}

async fn render_webmail(State(store): State<Arc<dyn MailStore>>) -> Response {
    let username = store.username();
    let address = store.account_address();
    let display_name = humanize_slug(&username);
    let rendered = WEBMAIL_HTML
        .replace("{{username}}", &escape_html(&username))
        .replace("{{email_address}}", &escape_html(&address))
        .replace("{{display_name}}", &escape_html(&display_name));
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
        ],
        Html(rendered),
    )
        .into_response()
}

async fn get_account(State(state): State<MailRouterState>) -> Response {
    match state.store.account_status(state.mailer.is_some()) {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn get_folders(State(state): State<MailRouterState>) -> Response {
    match state.store.folder_counts() {
        Ok(folders) => (StatusCode::OK, Json(folders)).into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn list_messages(
    State(state): State<MailRouterState>,
    Query(query): Query<ListMessagesQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(100);
    let unread_only = query.unread_only.unwrap_or(false);
    match state.store.list_messages(
        query.folder.as_deref(),
        query.q.as_deref(),
        unread_only,
        limit,
    ) {
        Ok(messages) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "address": state.store.account_address(),
                "messages": messages,
            })),
        )
            .into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn get_message(State(state): State<MailRouterState>, Path(id): Path<String>) -> Response {
    match state.store.get_message(&id) {
        Ok(Some(msg)) => (StatusCode::OK, Json(msg)).into_response(),
        Ok(None) => mail_error_response(MailError::NotFound(id)),
        Err(err) => mail_error_response(err),
    }
}

async fn patch_message(
    State(state): State<MailRouterState>,
    Path(id): Path<String>,
    Json(patch): Json<MailMessagePatch>,
) -> Response {
    match state.store.update_message_flags(&id, patch) {
        Ok(msg) => (StatusCode::OK, Json(msg)).into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn post_inbound(
    State(state): State<MailRouterState>,
    Json(payload): Json<InboundEmailPayload>,
) -> Response {
    match state.store.ingest_inbound(payload) {
        Ok(msg) => (StatusCode::CREATED, Json(msg)).into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn list_drafts(State(state): State<MailRouterState>) -> Response {
    match state.store.list_drafts() {
        Ok(drafts) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "drafts": drafts,
            })),
        )
            .into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn save_draft(
    State(state): State<MailRouterState>,
    Json(draft): Json<MailDraft>,
) -> Response {
    match state.store.save_draft(draft) {
        Ok(saved) => (StatusCode::OK, Json(saved)).into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn delete_draft(State(state): State<MailRouterState>, Path(id): Path<String>) -> Response {
    match state.store.delete_draft(&id) {
        Ok(deleted) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "deleted": deleted,
            })),
        )
            .into_response(),
        Err(err) => mail_error_response(err),
    }
}

async fn post_send(
    State(state): State<MailRouterState>,
    Json(req): Json<SendEmailRequest>,
) -> Response {
    if req.to.is_empty() {
        return mail_error_response(MailError::InvalidInput(
            "at least one recipient in 'to' is required".to_string(),
        ));
    }
    let from_addr = state.store.account_address();
    let username = state.store.username();
    let default_name = humanize_slug(&username);
    let from_name = req.from_name.as_deref().unwrap_or(&default_name);
    let message_id_header = format!("<msg-{}@proxy.ing>", random_hex_id());
    let raw_mime = build_raw_rfc5322(&from_addr, Some(from_name), &req, &message_id_header);

    if let Some(mailer) = &state.mailer
        && let Err(err) = mailer
            .send_raw_mime(&from_addr, &req.to, &raw_mime, &req)
            .await
    {
        return mail_error_response(err);
    }

    match state.store.record_sent_message(&req, message_id_header) {
        Ok(sent) => {
            if let Some(draft_id) = &req.draft_id {
                let _ = state.store.delete_draft(draft_id);
            }
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "message": sent,
                    "raw_rfc5322": raw_mime,
                })),
            )
                .into_response()
        }
        Err(err) => mail_error_response(err),
    }
}

fn mail_error_response(err: MailError) -> Response {
    let status = match err {
        MailError::NotFound(_) => StatusCode::NOT_FOUND,
        MailError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        MailError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
        MailError::Delivery(_) => StatusCode::BAD_GATEWAY,
    };
    (
        status,
        Json(json!({
            "ok": false,
            "error": err.to_string(),
        })),
    )
        .into_response()
}
