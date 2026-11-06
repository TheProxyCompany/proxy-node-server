//! Open-source `<username>@proxy.ing` email client, local mail store, RFC-5322
//! MIME parser/builder, and HTTP/Webmail routers.
//!
//! Hosted in `proxy-node-server` so anyone can inspect the `.proxy.ing` email
//! client, message storage model, inbound edge delivery contract, and outbound
//! MIME builder.

pub mod mime;
pub mod router;
pub mod store;
#[cfg(test)]
mod tests;

pub use mime::{ParsedMimeMessage, build_raw_rfc5322, parse_raw_rfc5322};
pub use router::{OutboundMailer, mail_router, webmail_router};
pub use store::{FileMailStore, MailMessagePatch, MailStore, MemoryMailStore};

use serde::{Deserialize, Serialize};

/// Canonical mail folders for a `<username>@proxy.ing` mailbox.
pub const MAIL_FOLDERS: &[&str] = &["inbox", "sent", "archive", "trash"];

/// File attachment carried on an inbound or sent [`MailMessage`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailAttachment {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub content_base64: String,
}

/// Stored email message in a `<username>@proxy.ing` mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailMessage {
    pub id: String,
    pub thread_id: String,
    pub account_address: String,
    pub folder: String,
    pub from: String,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    pub subject: String,
    pub snippet: String,
    pub text_body: String,
    #[serde(default)]
    pub html_body: Option<String>,
    pub message_id_header: String,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub unread: bool,
    pub starred: bool,
    #[serde(default)]
    pub spf_status: Option<String>,
    #[serde(default)]
    pub dkim_status: Option<String>,
    #[serde(default)]
    pub dmarc_status: Option<String>,
    pub received_at: String,
    #[serde(default)]
    pub attachments: Vec<MailAttachment>,
}

/// Saved draft message in a `<username>@proxy.ing` mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailDraft {
    pub id: String,
    pub account_address: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub text_body: String,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    pub updated_at: String,
}

/// Inbound email delivery payload posted by the `.proxy.ing` edge email worker
/// (`POST /client/v1/proxy-ing/mail/inbound` or `POST /v1/mail/inbound`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundEmailPayload {
    #[serde(default)]
    pub id: Option<String>,
    pub recipient: String,
    pub sender: String,
    #[serde(default)]
    pub sender_name: Option<String>,
    #[serde(default)]
    pub to: Option<Vec<String>>,
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub raw_rfc5322_base64: Option<String>,
    #[serde(default)]
    pub message_id_header: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub spf_status: Option<String>,
    #[serde(default)]
    pub dkim_status: Option<String>,
    #[serde(default)]
    pub dmarc_status: Option<String>,
    #[serde(default)]
    pub received_at: Option<String>,
    #[serde(default)]
    pub attachments: Option<Vec<MailAttachment>>,
}

/// Outbound email request submitted from the webmail client or CLI/MCP tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendEmailRequest {
    #[serde(default)]
    pub from_name: Option<String>,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    #[serde(default)]
    pub bcc: Option<Vec<String>>,
    #[serde(default)]
    pub reply_to: Option<String>,
    pub subject: String,
    pub text_body: String,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub draft_id: Option<String>,
}

/// Per-folder message count and unread count.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailFolderCount {
    pub folder: String,
    pub total: usize,
    pub unread: usize,
}

/// Summary status of the node's `<username>@proxy.ing` email account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailAccountStatus {
    pub username: String,
    pub address: String,
    pub display_name: String,
    pub provider: String,
    pub inbound_ready: bool,
    pub outbound_ready: bool,
    pub folders: Vec<MailFolderCount>,
}

/// Errors returned by mail store, MIME, and outbound dispatch operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MailError {
    #[error("mail message not found: {0}")]
    NotFound(String),
    #[error("invalid mail request: {0}")]
    InvalidInput(String),
    #[error("mail storage error: {0}")]
    Storage(String),
    #[error("outbound mail delivery failed: {0}")]
    Delivery(String),
}
