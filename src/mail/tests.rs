//! Unit and integration tests for `src/mail/` (MIME parser/builder,
//! `MemoryMailStore`, `FileMailStore`, HTTP `mail_router`, `webmail_router`, and
//! `net::gate` mail route helpers).

use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{
    FileMailStore, InboundEmailPayload, MailDraft, MailError, MailMessagePatch, MailStore,
    MemoryMailStore, OutboundMailer, SendEmailRequest, build_raw_rfc5322, mail_router,
    parse_raw_rfc5322, webmail_router,
};
use crate::net::gate::{
    EDGE_MAIL_DELIVERY_HEADER, family_of, is_edge_mail_inbound_request, is_public_pages_request,
};

struct RecordingMailer {
    sent: Mutex<Vec<(String, Vec<String>, String)>>,
}

impl RecordingMailer {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl OutboundMailer for RecordingMailer {
    async fn send_raw_mime(
        &self,
        from: &str,
        to: &[String],
        raw_rfc5322: &str,
        _req: &SendEmailRequest,
    ) -> Result<(), MailError> {
        self.sent
            .lock()
            .unwrap()
            .push((from.to_string(), to.to_vec(), raw_rfc5322.to_string()));
        Ok(())
    }
}

async fn serve_test_app(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

async fn send_req(
    base_url: &str,
    method: reqwest::Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let client = reqwest::Client::new();
    let mut builder = client.request(method, format!("{base_url}{uri}"));
    if let Some(v) = body {
        builder = builder
            .header("content-type", "application/json")
            .body(v.to_string());
    }
    let resp = builder.send().await.expect("send request");
    let status = StatusCode::from_u16(resp.status().as_u16()).expect("status");
    let text = resp.text().await.expect("body text");
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json, text)
}

#[test]
fn parse_and_build_rfc5322_roundtrip_and_multipart() {
    let req = SendEmailRequest {
        from_name: Some("Eden".to_string()),
        to: vec!["alex@proxy.ing".to_string()],
        cc: Some(vec!["team@proxy.ing".to_string()]),
        bcc: None,
        reply_to: Some("eden@proxy.ing".to_string()),
        subject: "Launch checklist".to_string(),
        text_body: "Plain text body for the checklist.".to_string(),
        html_body: Some("<p>HTML <strong>checklist</strong> body.</p>".to_string()),
        in_reply_to: Some("<parent-1@proxy.ing>".to_string()),
        references: Some(vec![
            "<root-0@proxy.ing>".to_string(),
            "<parent-1@proxy.ing>".to_string(),
        ]),
        draft_id: None,
    };
    let raw = build_raw_rfc5322("eden@proxy.ing", Some("Eden"), &req, "<msg-42@proxy.ing>");
    let parsed = parse_raw_rfc5322(raw.as_bytes());
    assert_eq!(parsed.from, "eden@proxy.ing");
    assert_eq!(parsed.from_name.as_deref(), Some("Eden"));
    assert_eq!(parsed.to, vec!["alex@proxy.ing".to_string()]);
    assert_eq!(parsed.cc, vec!["team@proxy.ing".to_string()]);
    assert_eq!(parsed.reply_to.as_deref(), Some("eden@proxy.ing"));
    assert_eq!(parsed.subject, "Launch checklist");
    assert_eq!(parsed.message_id.as_deref(), Some("<msg-42@proxy.ing>"));
    assert_eq!(parsed.in_reply_to.as_deref(), Some("<parent-1@proxy.ing>"));
    assert_eq!(parsed.references.len(), 2);
    assert_eq!(parsed.text_body, "Plain text body for the checklist.");
    assert_eq!(
        parsed.html_body.as_deref(),
        Some("<p>HTML <strong>checklist</strong> body.</p>")
    );
}

#[test]
fn parse_rfc5322_decodes_quoted_printable_and_base64_attachments() {
    let raw = concat!(
        "From: \"Jack Wind\" <jack@proxy.ing>\r\n",
        "To: eden@proxy.ing\r\n",
        "Subject: Open Source Email\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n",
        "--b1\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-Transfer-Encoding: quoted-printable\r\n\r\n",
        "Hello=20Proxy=20World!\r\n",
        "--b1\r\n",
        "Content-Type: text/plain; name=\"note.txt\"\r\n",
        "Content-Disposition: attachment; filename=\"note.txt\"\r\n",
        "Content-Transfer-Encoding: base64\r\n\r\n",
        "cHJveHktaW5n\r\n",
        "--b1--\r\n"
    );
    let parsed = parse_raw_rfc5322(raw.as_bytes());
    assert_eq!(parsed.from, "jack@proxy.ing");
    assert_eq!(parsed.from_name.as_deref(), Some("Jack Wind"));
    assert_eq!(parsed.text_body, "Hello Proxy World!");
    assert_eq!(parsed.attachments.len(), 1);
    assert_eq!(parsed.attachments[0].filename, "note.txt");
    assert_eq!(parsed.attachments[0].size_bytes, 9);
}

#[test]
fn file_mail_store_persists_messages_drafts_and_reads_domain_username() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("proxy-ing-domains.json"),
        r#"[{"username":"jappleseed","isEnabled":true}]"#,
    )
    .expect("write domains");

    let store = FileMailStore::new(dir.path(), "fallback");
    assert_eq!(store.username(), "jappleseed");
    assert_eq!(store.account_address(), "jappleseed@proxy.ing");

    let inbound = store
        .ingest_inbound(InboundEmailPayload {
            recipient: "jappleseed@proxy.ing".to_string(),
            sender: "alice@example.com".to_string(),
            sender_name: Some("Alice".to_string()),
            subject: Some("Welcome to proxy.ing".to_string()),
            text_body: Some("Inspectable open-source webmail.".to_string()),
            ..Default::default()
        })
        .expect("ingest inbound");
    assert!(inbound.unread);
    assert_eq!(inbound.folder, "inbox");

    let draft = store
        .save_draft(MailDraft {
            id: String::new(),
            account_address: String::new(),
            to: vec!["bob@example.com".to_string()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Draft subject".to_string(),
            text_body: "Draft body".to_string(),
            html_body: None,
            in_reply_to: None,
            updated_at: String::new(),
        })
        .expect("save draft");

    // Re-open store from disk to verify persistence
    let reopened = FileMailStore::new(dir.path(), "fallback");
    let listed = reopened
        .list_messages(Some("inbox"), Some("open-source"), true, 50)
        .expect("list messages");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, inbound.id);

    let updated = reopened
        .update_message_flags(
            &inbound.id,
            MailMessagePatch {
                unread: Some(false),
                starred: Some(true),
                folder: Some("archive".to_string()),
            },
        )
        .expect("update flags");
    assert!(!updated.unread);
    assert!(updated.starred);
    assert_eq!(updated.folder, "archive");

    let drafts = reopened.list_drafts().expect("list drafts");
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].id, draft.id);
    assert!(reopened.delete_draft(&draft.id).expect("delete draft"));
    assert!(reopened.list_drafts().expect("list drafts").is_empty());
}

#[tokio::test]
async fn mail_and_webmail_routers_handle_full_lifecycle() {
    let store = Arc::new(MemoryMailStore::new("eden"));
    let mailer = Arc::new(RecordingMailer::new());
    let api = mail_router(
        store.clone(),
        Some(mailer.clone() as Arc<dyn OutboundMailer>),
    );
    let api_base = serve_test_app(api).await;

    let raw_mime = concat!(
        "From: \"Satoshi\" <satoshi@gmx.com>\r\n",
        "To: eden@proxy.ing\r\n",
        "Subject: P2P Cash\r\n",
        "Message-ID: <p2p-1@gmx.com>\r\n\r\n",
        "Checking out eden@proxy.ing."
    );
    let (status, created, _) = send_req(
        &api_base,
        reqwest::Method::POST,
        "/inbound",
        Some(serde_json::json!({
            "recipient": "eden@proxy.ing",
            "sender": "satoshi@gmx.com",
            "raw_rfc5322_base64": STANDARD.encode(raw_mime.as_bytes()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let msg_id = created["id"].as_str().expect("msg id").to_string();
    assert_eq!(created["subject"], "P2P Cash");

    let (status, account, _) = send_req(&api_base, reqwest::Method::GET, "/account", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(account["address"], "eden@proxy.ing");
    assert_eq!(account["outbound_ready"], true);

    let (status, list_res, _) = send_req(
        &api_base,
        reqwest::Method::GET,
        "/messages?folder=inbox&unread_only=true",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list_res["messages"].as_array().unwrap().len(), 1);

    let (status, patched, _) = send_req(
        &api_base,
        reqwest::Method::PATCH,
        &format!("/messages/{msg_id}"),
        Some(serde_json::json!({ "unread": false, "starred": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["unread"], false);
    assert_eq!(patched["starred"], true);

    let (status, sent_res, _) = send_req(
        &api_base,
        reqwest::Method::POST,
        "/send",
        Some(serde_json::json!({
            "to": ["satoshi@gmx.com"],
            "subject": "Re: P2P Cash",
            "text_body": "Received loud and clear.",
            "in_reply_to": "<p2p-1@gmx.com>"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sent_res["ok"], true);
    assert_eq!(sent_res["message"]["folder"], "sent");
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);

    let web_base = serve_test_app(webmail_router(store)).await;
    let (status, _, html) = send_req(&web_base, reqwest::Method::GET, "/inbox", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("eden@proxy.ing"));
    assert!(html.contains("SPF/DKIM Verified"));
}

#[test]
fn gate_recognizes_public_inbox_edge_inbound_and_mail_family() {
    assert!(is_public_pages_request(&Method::GET, "/inbox"));
    assert!(is_public_pages_request(&Method::GET, "/client/inbox"));
    assert!(is_public_pages_request(&Method::GET, "/p/_mail"));
    assert!(is_public_pages_request(&Method::GET, "/p/_profile.json"));

    let mut headers = HeaderMap::new();
    headers.insert(EDGE_MAIL_DELIVERY_HEADER, HeaderValue::from_static("1"));
    assert!(is_edge_mail_inbound_request(
        &Method::POST,
        "/client/v1/proxy-ing/mail/inbound",
        &headers
    ));
    assert!(is_edge_mail_inbound_request(
        &Method::POST,
        "/v1/mail/inbound",
        &headers
    ));
    assert!(!is_edge_mail_inbound_request(
        &Method::GET,
        "/v1/mail/inbound",
        &headers
    ));

    assert_eq!(
        family_of(&Method::GET, "/client/v1/proxy-ing/mail/messages"),
        Some("mail")
    );
    assert_eq!(family_of(&Method::POST, "/v1/mail/send"), Some("mail"));
}
