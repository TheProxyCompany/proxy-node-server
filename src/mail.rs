//! Open-source `<username>@proxy.ing` Email Client, RFC 5322 / MIME parser, and Mail Store.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::address::{DOMAIN, normalize_user};

/// Formats a canonical `<username>@proxy.ing` email address.
pub fn format_proxy_ing_email(username: &str) -> String {
    let trimmed = username
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches(&format!("@{DOMAIN}"))
        .trim_end_matches(&format!(".{DOMAIN}"))
        .to_string();
    let user = normalize_user(&trimmed).unwrap_or(trimmed);
    format!("{user}@{DOMAIN}")
}

/// Parses an email header/address string (e.g. `"Alex <alex@proxy.ing>"` or `"alex@proxy.ing"`)
/// and returns the canonical `<username>` if it belongs to `@proxy.ing`.
pub fn parse_proxy_ing_email(addr: &str) -> Option<String> {
    let candidate = match addr.rsplit_once('<') {
        Some((_, after)) => after.split('>').next().unwrap_or(after).trim(),
        None => addr.trim(),
    };
    let (local, domain) = candidate.trim_matches('"').trim().split_once('@')?;
    domain
        .eq_ignore_ascii_case(DOMAIN)
        .then(|| normalize_user(local.split('+').next().unwrap_or(local)).ok())
        .flatten()
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MailDirection {
    Inbound,
    Outbound,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MailAttachment {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct MailMessage {
    pub id: String,
    pub thread_id: String,
    pub username: String,
    pub direction: MailDirection,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub text_body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
    pub raw_headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub unread: bool,
    pub starred: bool,
    pub archived: bool,
    pub created_at_ms: u64,
    pub attachments: Vec<MailAttachment>,
}

impl Default for MailMessage {
    fn default() -> Self {
        Self {
            id: String::new(),
            thread_id: String::new(),
            username: String::new(),
            direction: MailDirection::Inbound,
            from: String::new(),
            to: Vec::new(),
            cc: Vec::new(),
            subject: String::new(),
            text_body: String::new(),
            html_body: None,
            raw_headers: BTreeMap::new(),
            in_reply_to: None,
            references: Vec::new(),
            unread: true,
            starred: false,
            archived: false,
            created_at_ms: 0,
            attachments: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(default)]
pub struct InboundEmailWebhookPayload {
    pub id: Option<String>,
    pub recipient: String,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub raw_mime: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub received_at: Option<u64>,
    pub attachments: Vec<MailAttachment>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(default)]
pub struct SendMailRequest {
    pub from_username: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text_body: String,
    pub html_body: Option<String>,
    pub in_reply_to: Option<String>,
    pub thread_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ParsedMimeEmail {
    pub headers: BTreeMap<String, String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub date: Option<String>,
    pub text_body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<MailAttachment>,
}

pub fn normalize_subject(subject: &str) -> String {
    let mut cur = subject.trim();
    while let Some(rest) = ["re:", "fwd:", "fw:"]
        .iter()
        .find_map(|p| cur.to_ascii_lowercase().strip_prefix(p).map(|r| &cur[cur.len() - r.len()..]))
    {
        cur = rest.trim();
    }
    cur.to_string()
}

pub fn derive_thread_id(
    subject: &str,
    message_id: Option<&str>,
    in_reply_to: Option<&str>,
    references: &[String],
) -> String {
    let norm = normalize_subject(subject);
    let anchor = references
        .first()
        .map(String::as_str)
        .or(in_reply_to)
        .or(if norm.is_empty() { message_id } else { None });
    let seed = match anchor {
        Some(a) => format!("ref:{}", a.trim().to_ascii_lowercase()),
        None if norm.is_empty() => format!(
            "msg:{}",
            message_id.unwrap_or("anonymous").trim().to_ascii_lowercase()
        ),
        None => format!("subj:{}", norm.to_ascii_lowercase()),
    };
    format!("thr_{}", hex::encode(&Sha256::digest(seed.as_bytes())[..8]))
}

fn split_headers_and_body(raw: &str) -> (&str, &str) {
    raw.split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .unwrap_or((raw, ""))
}

fn parse_headers(header_block: &str) -> BTreeMap<String, String> {
    let mut unfolded: Vec<String> = Vec::new();
    for line in header_block.lines() {
        let line = line.trim_end_matches('\r');
        if (line.starts_with(' ') || line.starts_with('\t'))
            && let Some(last) = unfolded.last_mut()
        {
            last.push(' ');
            last.push_str(line.trim());
        } else if !line.is_empty() {
            unfolded.push(line.to_string());
        }
    }
    unfolded
        .into_iter()
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect()
}

fn extract_param(header_val: &str, param_name: &str) -> Option<String> {
    header_val.split(';').skip(1).find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case(param_name).then(|| v.trim().trim_matches('"').to_string())
    })
}

fn decode_quoted_printable(input: &str) -> String {
    let (mut bytes, raw, mut i) = (Vec::with_capacity(input.len()), input.as_bytes(), 0);
    while i < raw.len() {
        if raw[i] == b'=' {
            if i + 2 < raw.len() && raw[i + 1] == b'\r' && raw[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if i + 2 < raw.len()
                && let (Some(h), Some(l)) = ((raw[i + 1] as char).to_digit(16), (raw[i + 2] as char).to_digit(16))
            {
                bytes.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        bytes.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decode_part_body(body: &str, transfer_encoding: Option<&str>) -> String {
    match transfer_encoding.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("quoted-printable") => decode_quoted_printable(body),
        Some("base64") => {
            use base64::Engine;
            let cleaned: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| body.to_string())
        }
        _ => body.to_string(),
    }
}

fn parse_mime_entity(
    headers: &BTreeMap<String, String>,
    body: &str,
    text_out: &mut Option<String>,
    html_out: &mut Option<String>,
    attachments: &mut Vec<MailAttachment>,
) {
    let content_type = headers.get("content-type").cloned().unwrap_or_else(|| "text/plain".to_string());
    let ct_lower = content_type.to_ascii_lowercase();
    let disposition = headers.get("content-disposition").cloned().unwrap_or_default();
    let transfer_encoding = headers.get("content-transfer-encoding").map(String::as_str);

    if ct_lower.starts_with("multipart/")
        && let Some(boundary) = extract_param(&content_type, "boundary")
    {
        let (delimiter, end_delimiter) = (format!("--{boundary}"), format!("--{boundary}--"));
        for section in body.split(&delimiter).skip(1) {
            let trimmed = section.trim_start_matches("\r\n").trim_start_matches('\n');
            if trimmed.starts_with("--") || section.starts_with(&end_delimiter) {
                break;
            }
            let cleaned = trimmed.strip_suffix("\r\n").or_else(|| trimmed.strip_suffix('\n')).unwrap_or(trimmed);
            let (part_hdr_raw, part_body) = split_headers_and_body(cleaned);
            parse_mime_entity(&parse_headers(part_hdr_raw), part_body, text_out, html_out, attachments);
        }
        return;
    }

    let filename = extract_param(&disposition, "filename").or_else(|| extract_param(&content_type, "name"));
    if disposition.to_ascii_lowercase().starts_with("attachment") || filename.is_some() {
        let cleaned = body.trim();
        attachments.push(MailAttachment {
            filename: filename.unwrap_or_else(|| "attachment.bin".to_string()),
            content_type: content_type.split(';').next().unwrap_or("application/octet-stream").trim().to_string(),
            size_bytes: cleaned.len(),
            content_base64: Some(cleaned.to_string()),
        });
        return;
    }

    let decoded = decode_part_body(body, transfer_encoding);
    if ct_lower.starts_with("text/html") {
        if html_out.is_none() {
            *html_out = Some(decoded.trim().to_string());
        }
    } else if text_out.is_none() {
        *text_out = Some(decoded.trim().to_string());
    }
}

fn split_address_list(raw: Option<&String>) -> Vec<String> {
    raw.map(|s| s.split(',').map(str::trim).filter(|p| !p.is_empty()).map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// Parses a raw RFC 5322 / MIME email into headers, text/HTML bodies, and attachments.
pub fn parse_raw_email(raw: &str) -> ParsedMimeEmail {
    let (hdr_block, body) = split_headers_and_body(raw);
    let headers = parse_headers(hdr_block);
    let (mut text_out, mut html_out, mut attachments) = (None, None, Vec::new());
    parse_mime_entity(&headers, body, &mut text_out, &mut html_out, &mut attachments);
    let references = headers
        .get("references")
        .map(|r| r.split_whitespace().map(ToString::to_string).collect())
        .unwrap_or_default();
    ParsedMimeEmail {
        from: headers.get("from").cloned(),
        to: split_address_list(headers.get("to")),
        cc: split_address_list(headers.get("cc")),
        subject: headers.get("subject").cloned(),
        message_id: headers.get("message-id").cloned(),
        in_reply_to: headers.get("in-reply-to").cloned(),
        references,
        date: headers.get("date").cloned(),
        text_body: text_out.unwrap_or_default(),
        html_body: html_out,
        attachments,
        headers,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Thread-safe in-memory and optional JSON-lines backed Mail Store.
#[derive(Default)]
pub struct MailStore {
    messages: Mutex<Vec<MailMessage>>,
    #[allow(dead_code)]
    persistence_path: Option<PathBuf>,
}

impl MailStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_persistence_path(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            messages: Mutex::new(Self::load_from_disk(&path)),
            persistence_path: Some(path),
        }
    }

    #[cfg(feature = "daemon")]
    fn load_from_disk(path: &PathBuf) -> Vec<MailMessage> {
        std::fs::read_to_string(path)
            .ok()
            .map(|c| c.lines().filter_map(|l| serde_json::from_str::<MailMessage>(l).ok()).collect())
            .unwrap_or_default()
    }

    #[cfg(not(feature = "daemon"))]
    fn load_from_disk(_path: &PathBuf) -> Vec<MailMessage> {
        Vec::new()
    }

    #[cfg(feature = "daemon")]
    fn flush_to_disk(&self, messages: &[MailMessage]) {
        let Some(path) = &self.persistence_path else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let out: String = messages
            .iter()
            .filter_map(|m| serde_json::to_string(m).ok().map(|s| format!("{s}\n")))
            .collect();
        let _ = std::fs::write(path, out);
    }

    #[cfg(not(feature = "daemon"))]
    fn flush_to_disk(&self, _messages: &[MailMessage]) {}

    pub fn ingest_inbound(&self, payload: InboundEmailWebhookPayload) -> MailMessage {
        let parsed = payload.raw_mime.as_deref().map(parse_raw_email).unwrap_or_default();
        let mut raw_headers = parsed.headers;
        for (k, v) in payload.headers {
            raw_headers.insert(k.to_ascii_lowercase(), v);
        }
        let from = if !payload.from.trim().is_empty() {
            payload.from
        } else {
            parsed.from.unwrap_or_else(|| "unknown@proxy.ing".to_string())
        };
        let to = if !payload.to.is_empty() {
            payload.to
        } else if !parsed.to.is_empty() {
            parsed.to
        } else {
            vec![payload.recipient.clone()]
        };
        let cc = if !payload.cc.is_empty() { payload.cc } else { parsed.cc };
        let subject = payload.subject.or(parsed.subject).unwrap_or_else(|| "(no subject)".to_string());
        let text_body = payload.text_body.unwrap_or(parsed.text_body);
        let html_body = payload.html_body.or(parsed.html_body);
        let in_reply_to = raw_headers.get("in-reply-to").cloned().or(parsed.in_reply_to);
        let references = if !parsed.references.is_empty() {
            parsed.references
        } else {
            raw_headers
                .get("references")
                .map(|r| r.split_whitespace().map(ToString::to_string).collect())
                .unwrap_or_default()
        };
        let created_at_ms = payload.received_at.unwrap_or_else(now_unix_ms);
        let id = payload
            .id
            .or_else(|| raw_headers.get("message-id").cloned())
            .or(parsed.message_id)
            .unwrap_or_else(|| {
                let d = Sha256::digest(format!("{from}:{}:{subject}:{created_at_ms}", payload.recipient).as_bytes());
                format!("msg_{}", hex::encode(&d[..8]))
            });
        let thread_id = derive_thread_id(&subject, Some(&id), in_reply_to.as_deref(), &references);
        let username = parse_proxy_ing_email(&payload.recipient)
            .or_else(|| to.iter().find_map(|addr| parse_proxy_ing_email(addr)))
            .unwrap_or_else(|| payload.recipient.split('@').next().unwrap_or("proxy").trim().to_ascii_lowercase());
        let attachments = if !payload.attachments.is_empty() { payload.attachments } else { parsed.attachments };
        let msg = MailMessage {
            id,
            thread_id,
            username,
            direction: MailDirection::Inbound,
            from,
            to,
            cc,
            subject,
            text_body,
            html_body,
            raw_headers,
            in_reply_to,
            references,
            unread: true,
            starred: false,
            archived: false,
            created_at_ms,
            attachments,
        };
        let mut guard = self.messages.lock().expect("mail store lock");
        if let Some(existing) = guard.iter().find(|m| m.id == msg.id).cloned() {
            return existing;
        }
        guard.push(msg.clone());
        self.flush_to_disk(&guard);
        msg
    }

    pub fn record_outbound(
        &self,
        username: &str,
        req: SendMailRequest,
        message_id: String,
        now_ms: u64,
    ) -> MailMessage {
        let from_email = format_proxy_ing_email(username);
        let clean_user = parse_proxy_ing_email(&from_email).unwrap_or_else(|| username.to_string());
        let references: Vec<String> = req.in_reply_to.iter().cloned().collect();
        let thread_id = req.thread_id.unwrap_or_else(|| {
            derive_thread_id(&req.subject, Some(&message_id), req.in_reply_to.as_deref(), &references)
        });
        let msg = MailMessage {
            id: message_id,
            thread_id,
            username: clean_user,
            direction: MailDirection::Outbound,
            from: from_email,
            to: req.to,
            cc: req.cc,
            subject: req.subject,
            text_body: req.text_body,
            html_body: req.html_body,
            raw_headers: BTreeMap::new(),
            in_reply_to: req.in_reply_to,
            references,
            unread: false,
            starred: false,
            archived: false,
            created_at_ms: now_ms,
            attachments: Vec::new(),
        };
        let mut guard = self.messages.lock().expect("mail store lock");
        guard.push(msg.clone());
        self.flush_to_disk(&guard);
        msg
    }

    pub fn list_messages(&self, folder: Option<&str>, limit: usize) -> Vec<MailMessage> {
        let guard = self.messages.lock().expect("mail store lock");
        let folder_norm = folder.map(|f| f.trim().to_ascii_lowercase());
        let mut filtered: Vec<MailMessage> = guard
            .iter()
            .filter(|m| match folder_norm.as_deref() {
                None | Some("") | Some("all") => true,
                Some("inbox") => m.direction == MailDirection::Inbound && !m.archived,
                Some("sent") => m.direction == MailDirection::Outbound && !m.archived,
                Some("starred") => m.starred,
                Some("unread") => m.unread && !m.archived,
                Some("archived") => m.archived,
                _ => true,
            })
            .cloned()
            .collect();
        filtered.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        if limit > 0 && filtered.len() > limit {
            filtered.truncate(limit);
        }
        filtered
    }

    pub fn get_message(&self, id: &str) -> Option<MailMessage> {
        self.messages.lock().expect("mail store lock").iter().find(|m| m.id == id).cloned()
    }

    fn mutate_message(&self, id: &str, f: impl FnOnce(&mut MailMessage)) -> bool {
        let mut guard = self.messages.lock().expect("mail store lock");
        let Some(msg) = guard.iter_mut().find(|m| m.id == id) else {
            return false;
        };
        f(msg);
        self.flush_to_disk(&guard);
        true
    }

    pub fn mark_read(&self, id: &str, unread: bool) -> bool {
        self.mutate_message(id, |m| m.unread = unread)
    }

    pub fn set_starred(&self, id: &str, starred: bool) -> bool {
        self.mutate_message(id, |m| m.starred = starred)
    }

    pub fn set_archived(&self, id: &str, archived: bool) -> bool {
        self.mutate_message(id, |m| m.archived = archived)
    }
}

#[cfg(feature = "pull-http")]
mod http {
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::{Query, State},
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
    };
    use serde::Deserialize;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{InboundEmailWebhookPayload, MailStore, SendMailRequest, now_unix_ms};

    #[derive(Deserialize, Default)]
    pub struct ListMailQuery {
        pub folder: Option<String>,
        pub limit: Option<usize>,
    }

    async fn handle_inbound(
        State(store): State<Arc<MailStore>>,
        Json(payload): Json<InboundEmailWebhookPayload>,
    ) -> impl IntoResponse {
        let msg = store.ingest_inbound(payload);
        (StatusCode::OK, Json(json!({ "ok": true, "message": msg })))
    }

    async fn handle_list_messages(
        State(store): State<Arc<MailStore>>,
        Query(query): Query<ListMailQuery>,
    ) -> impl IntoResponse {
        let messages = store.list_messages(query.folder.as_deref(), query.limit.unwrap_or(100));
        (StatusCode::OK, Json(json!({ "messages": messages, "count": messages.len() })))
    }

    async fn handle_send(
        State(store): State<Arc<MailStore>>,
        Json(req): Json<SendMailRequest>,
    ) -> impl IntoResponse {
        if req.to.is_empty() {
            return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": "missing_recipient" })));
        }
        let now_ms = now_unix_ms();
        let username = req.from_username.clone().unwrap_or_else(|| "proxy".to_string());
        let digest = Sha256::digest(format!("{username}:{}:{}:{now_ms}", req.to.join(","), req.subject).as_bytes());
        let msg_id = format!("out_{}", hex::encode(&digest[..8]));
        let msg = store.record_outbound(&username, req, msg_id, now_ms);
        (StatusCode::OK, Json(json!({ "ok": true, "message": msg })))
    }

    pub fn mail_router(store: Arc<MailStore>) -> Router {
        Router::new()
            .route("/client/v1/proxy-ing/mail/inbound", post(handle_inbound))
            .route("/v1/mail/inbound", post(handle_inbound))
            .route("/client/v1/proxy-ing/mail/messages", get(handle_list_messages))
            .route("/v1/mail/messages", get(handle_list_messages))
            .route("/client/v1/proxy-ing/mail/send", post(handle_send))
            .route("/v1/mail/send", post(handle_send))
            .with_state(store)
    }
}

#[cfg(feature = "pull-http")]
pub use http::mail_router;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_proxy_ing_emails() {
        assert_eq!(format_proxy_ing_email("alex"), "alex@proxy.ing");
        assert_eq!(format_proxy_ing_email("Alex.Proxy.Ing"), "alex@proxy.ing");
        assert_eq!(parse_proxy_ing_email("Alex Smith <alex-smith@proxy.ing>"), Some("alex-smith".to_string()));
        assert_eq!(parse_proxy_ing_email("alex+tag@PROXY.ING"), Some("alex".to_string()));
        assert_eq!(parse_proxy_ing_email("alex@example.com"), None);
        assert_eq!(parse_proxy_ing_email("ab@proxy.ing"), None);
    }

    #[test]
    fn parses_multipart_mime_email_and_headers() {
        let raw = concat!(
            "From: Sender <sender@example.com>\r\n",
            "To: Alex <alex@proxy.ing>\r\n",
            "Subject: Re: Project\r\n \tUpdate\r\n",
            "Message-ID: <msg-2@example.com>\r\n",
            "In-Reply-To: <msg-1@example.com>\r\n",
            "References: <msg-0@example.com> <msg-1@example.com>\r\n",
            "Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n",
            "--b1\r\nContent-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n\r\nHello=20World!\r\n",
            "--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <b>World!</b></p>\r\n",
            "--b1--\r\n"
        );
        let parsed = parse_raw_email(raw);
        assert_eq!(parsed.from.as_deref(), Some("Sender <sender@example.com>"));
        assert_eq!(parsed.to, vec!["Alex <alex@proxy.ing>"]);
        assert_eq!(parsed.subject.as_deref(), Some("Re: Project Update"));
        assert_eq!(parsed.message_id.as_deref(), Some("<msg-2@example.com>"));
        assert_eq!(parsed.in_reply_to.as_deref(), Some("<msg-1@example.com>"));
        assert_eq!(parsed.references, vec!["<msg-0@example.com>", "<msg-1@example.com>"]);
        assert_eq!(parsed.text_body, "Hello World!");
        assert_eq!(parsed.html_body.as_deref(), Some("<p>Hello <b>World!</b></p>"));
    }

    #[test]
    fn groups_threads_deterministically() {
        let t1 = derive_thread_id("Launch Plan", Some("<m1@x>"), None, &[]);
        let t2 = derive_thread_id("Re: Fwd: launch plan", Some("<m2@x>"), None, &[]);
        assert_eq!(t1, t2);
        let r1 = derive_thread_id("Different Subject", Some("<m3@x>"), Some("<root@x>"), &[]);
        let r2 = derive_thread_id("Another Subject", Some("<m4@x>"), Some("<m3@x>"), &["<root@x>".into(), "<m3@x>".into()]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn store_ingests_records_and_filters_messages() {
        let store = MailStore::new();
        let inbound = store.ingest_inbound(InboundEmailWebhookPayload {
            id: Some("in-1".to_string()),
            recipient: "alex@proxy.ing".to_string(),
            from: "founder@example.com".to_string(),
            subject: Some("Welcome".to_string()),
            text_body: Some("Hi Alex".to_string()),
            received_at: Some(1_000),
            ..Default::default()
        });
        assert_eq!(inbound.username, "alex");
        assert!(inbound.unread);

        let outbound = store.record_outbound(
            "alex",
            SendMailRequest {
                from_username: Some("alex".to_string()),
                to: vec!["founder@example.com".to_string()],
                subject: "Re: Welcome".to_string(),
                text_body: "Thanks!".to_string(),
                ..Default::default()
            },
            "out-1".to_string(),
            2_000,
        );
        assert_eq!(outbound.thread_id, inbound.thread_id);
        assert_eq!(store.list_messages(Some("inbox"), 10).len(), 1);
        assert_eq!(store.list_messages(Some("sent"), 10).len(), 1);
        assert_eq!(store.list_messages(Some("unread"), 10).len(), 1);
        assert!(store.mark_read("in-1", false));
        assert_eq!(store.list_messages(Some("unread"), 10).len(), 0);
        assert!(store.set_starred("out-1", true));
        assert_eq!(store.list_messages(Some("starred"), 10).len(), 1);
        assert!(store.set_archived("in-1", true));
        assert_eq!(store.list_messages(Some("inbox"), 10).len(), 0);
        assert_eq!(store.list_messages(Some("archived"), 10).len(), 1);
        assert!(store.get_message("in-1").unwrap().archived);
    }

    #[cfg(feature = "pull-http")]
    #[tokio::test]
    async fn mail_http_router_handles_inbound_list_and_send() {
        use std::sync::Arc;
        use tokio::net::TcpListener;

        let store = Arc::new(MailStore::new());
        let app = mail_router(store.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let inbound_resp = client
            .post(format!("http://{addr}/client/v1/proxy-ing/mail/inbound"))
            .json(&serde_json::json!({
                "id": "http-in-1",
                "recipient": "alex@proxy.ing",
                "from": "bob@example.com",
                "subject": "Hello over HTTP",
                "text_body": "Testing inbound webhook",
                "received_at": 100
            }))
            .send()
            .await
            .expect("inbound post");
        assert_eq!(inbound_resp.status(), 200);

        let send_resp = client
            .post(format!("http://{addr}/v1/mail/send"))
            .json(&serde_json::json!({
                "from_username": "alex",
                "to": ["bob@example.com"],
                "subject": "Re: Hello over HTTP",
                "text_body": "Reply from Alex"
            }))
            .send()
            .await
            .expect("send post");
        assert_eq!(send_resp.status(), 200);

        let list_resp: serde_json::Value = client
            .get(format!("http://{addr}/client/v1/proxy-ing/mail/messages?folder=all"))
            .send()
            .await
            .expect("list get")
            .json()
            .await
            .expect("list json");
        assert_eq!(list_resp["count"], 2);
    }
}
