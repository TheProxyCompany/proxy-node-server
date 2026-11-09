//! Local and in-memory mail stores for `<username>@proxy.ing`.

use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    InboundEmailPayload, MAIL_FOLDERS, MailAccountStatus, MailDraft, MailError, MailFolderCount,
    MailMessage, SendEmailRequest, humanize_slug, parse_raw_rfc5322,
};

/// Flag and folder mutation payload for `POST/PATCH /messages/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailMessagePatch {
    #[serde(default)]
    pub unread: Option<bool>,
    #[serde(default)]
    pub starred: Option<bool>,
    #[serde(default)]
    pub folder: Option<String>,
}

/// Pluggable storage backend for a `<username>@proxy.ing` mailbox.
pub trait MailStore: Send + Sync + 'static {
    fn username(&self) -> String;
    fn account_address(&self) -> String {
        format!("{}@proxy.ing", self.username())
    }
    fn ingest_inbound(&self, payload: InboundEmailPayload) -> Result<MailMessage, MailError>;
    fn list_messages(
        &self,
        folder: Option<&str>,
        query: Option<&str>,
        unread_only: bool,
        limit: usize,
    ) -> Result<Vec<MailMessage>, MailError>;
    fn get_message(&self, id: &str) -> Result<Option<MailMessage>, MailError>;
    fn update_message_flags(
        &self,
        id: &str,
        patch: MailMessagePatch,
    ) -> Result<MailMessage, MailError>;
    fn save_draft(&self, draft: MailDraft) -> Result<MailDraft, MailError>;
    fn list_drafts(&self) -> Result<Vec<MailDraft>, MailError>;
    fn delete_draft(&self, id: &str) -> Result<bool, MailError>;
    fn record_sent_message(
        &self,
        req: &SendEmailRequest,
        message_id_header: String,
    ) -> Result<MailMessage, MailError>;
    fn folder_counts(&self) -> Result<Vec<MailFolderCount>, MailError>;
    fn account_status(&self, outbound_ready: bool) -> Result<MailAccountStatus, MailError> {
        let username = self.username();
        let address = self.account_address();
        let display_name = humanize_slug(&username);
        let folders = self.folder_counts()?;
        Ok(MailAccountStatus {
            username,
            address,
            display_name,
            provider: "proxy.ing".to_string(),
            inbound_ready: true,
            outbound_ready,
            folders,
        })
    }
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|p| p.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|p| p.into_inner())
}

#[derive(Default)]
struct StoreData {
    messages: Vec<MailMessage>,
    drafts: Vec<MailDraft>,
}

/// Thread-safe in-memory [`MailStore`].
pub struct MemoryMailStore {
    username: String,
    inner: RwLock<StoreData>,
}

impl MemoryMailStore {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: normalize_username(&username.into()),
            inner: RwLock::new(StoreData::default()),
        }
    }
}

impl MailStore for MemoryMailStore {
    fn username(&self) -> String {
        self.username.clone()
    }

    fn ingest_inbound(&self, payload: InboundEmailPayload) -> Result<MailMessage, MailError> {
        let msg = build_inbound_message(&self.account_address(), payload)?;
        let mut guard = write_lock(&self.inner);
        guard.messages.retain(|existing| existing.id != msg.id);
        guard.messages.insert(0, msg.clone());
        Ok(msg)
    }

    fn list_messages(
        &self,
        folder: Option<&str>,
        query: Option<&str>,
        unread_only: bool,
        limit: usize,
    ) -> Result<Vec<MailMessage>, MailError> {
        let guard = read_lock(&self.inner);
        Ok(filter_messages(
            &guard.messages,
            folder,
            query,
            unread_only,
            limit,
        ))
    }

    fn get_message(&self, id: &str) -> Result<Option<MailMessage>, MailError> {
        Ok(read_lock(&self.inner)
            .messages
            .iter()
            .find(|m| m.id == id)
            .cloned())
    }

    fn update_message_flags(
        &self,
        id: &str,
        patch: MailMessagePatch,
    ) -> Result<MailMessage, MailError> {
        let mut guard = write_lock(&self.inner);
        let msg = guard
            .messages
            .iter_mut()
            .find(|m| m.id == id)
            .ok_or_else(|| MailError::NotFound(id.to_string()))?;
        apply_patch(msg, patch)?;
        Ok(msg.clone())
    }

    fn save_draft(&self, mut draft: MailDraft) -> Result<MailDraft, MailError> {
        if draft.id.trim().is_empty() {
            draft.id = format!("draft-{}", random_hex_id());
        }
        draft.account_address = self.account_address();
        draft.updated_at = now_iso8601();
        let mut guard = write_lock(&self.inner);
        guard.drafts.retain(|d| d.id != draft.id);
        guard.drafts.insert(0, draft.clone());
        Ok(draft)
    }

    fn list_drafts(&self) -> Result<Vec<MailDraft>, MailError> {
        Ok(read_lock(&self.inner).drafts.clone())
    }

    fn delete_draft(&self, id: &str) -> Result<bool, MailError> {
        let mut guard = write_lock(&self.inner);
        let before = guard.drafts.len();
        guard.drafts.retain(|d| d.id != id);
        Ok(guard.drafts.len() < before)
    }

    fn record_sent_message(
        &self,
        req: &SendEmailRequest,
        message_id_header: String,
    ) -> Result<MailMessage, MailError> {
        let msg = build_sent_message(
            &self.account_address(),
            &self.username,
            req,
            message_id_header,
        )?;
        write_lock(&self.inner).messages.insert(0, msg.clone());
        Ok(msg)
    }

    fn folder_counts(&self) -> Result<Vec<MailFolderCount>, MailError> {
        Ok(compute_folder_counts(&read_lock(&self.inner).messages))
    }
}

/// File-backed [`MailStore`] persisting `<data_dir>/mail/messages.json` and
/// `<data_dir>/mail/drafts.json` atomically.
pub struct FileMailStore {
    data_dir: PathBuf,
    fallback_username: String,
    lock: RwLock<()>,
}

impl FileMailStore {
    pub fn new(data_dir: impl AsRef<Path>, fallback_username: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
            fallback_username: normalize_username(&fallback_username.into()),
            lock: RwLock::new(()),
        }
    }

    fn messages_path(&self) -> PathBuf {
        self.data_dir.join("mail").join("messages.json")
    }

    fn drafts_path(&self) -> PathBuf {
        self.data_dir.join("mail").join("drafts.json")
    }

    fn read_messages_unlocked(&self) -> Vec<MailMessage> {
        std::fs::read(self.messages_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write_messages_unlocked(&self, messages: &[MailMessage]) -> Result<(), MailError> {
        write_json_atomic(&self.messages_path(), messages)
    }

    fn read_drafts_unlocked(&self) -> Vec<MailDraft> {
        std::fs::read(self.drafts_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write_drafts_unlocked(&self, drafts: &[MailDraft]) -> Result<(), MailError> {
        write_json_atomic(&self.drafts_path(), drafts)
    }
}

impl MailStore for FileMailStore {
    fn username(&self) -> String {
        resolve_domain_username(&self.data_dir.join("proxy-ing-domains.json"))
            .unwrap_or_else(|| self.fallback_username.clone())
    }

    fn ingest_inbound(&self, payload: InboundEmailPayload) -> Result<MailMessage, MailError> {
        let msg = build_inbound_message(&self.account_address(), payload)?;
        let _guard = write_lock(&self.lock);
        let mut messages = self.read_messages_unlocked();
        messages.retain(|existing| existing.id != msg.id);
        messages.insert(0, msg.clone());
        self.write_messages_unlocked(&messages)?;
        Ok(msg)
    }

    fn list_messages(
        &self,
        folder: Option<&str>,
        query: Option<&str>,
        unread_only: bool,
        limit: usize,
    ) -> Result<Vec<MailMessage>, MailError> {
        let _guard = read_lock(&self.lock);
        let messages = self.read_messages_unlocked();
        Ok(filter_messages(
            &messages,
            folder,
            query,
            unread_only,
            limit,
        ))
    }

    fn get_message(&self, id: &str) -> Result<Option<MailMessage>, MailError> {
        let _guard = read_lock(&self.lock);
        Ok(self
            .read_messages_unlocked()
            .into_iter()
            .find(|m| m.id == id))
    }

    fn update_message_flags(
        &self,
        id: &str,
        patch: MailMessagePatch,
    ) -> Result<MailMessage, MailError> {
        let _guard = write_lock(&self.lock);
        let mut messages = self.read_messages_unlocked();
        let msg = messages
            .iter_mut()
            .find(|m| m.id == id)
            .ok_or_else(|| MailError::NotFound(id.to_string()))?;
        apply_patch(msg, patch)?;
        let updated = msg.clone();
        self.write_messages_unlocked(&messages)?;
        Ok(updated)
    }

    fn save_draft(&self, mut draft: MailDraft) -> Result<MailDraft, MailError> {
        if draft.id.trim().is_empty() {
            draft.id = format!("draft-{}", random_hex_id());
        }
        draft.account_address = self.account_address();
        draft.updated_at = now_iso8601();
        let _guard = write_lock(&self.lock);
        let mut drafts = self.read_drafts_unlocked();
        drafts.retain(|d| d.id != draft.id);
        drafts.insert(0, draft.clone());
        self.write_drafts_unlocked(&drafts)?;
        Ok(draft)
    }

    fn list_drafts(&self) -> Result<Vec<MailDraft>, MailError> {
        let _guard = read_lock(&self.lock);
        Ok(self.read_drafts_unlocked())
    }

    fn delete_draft(&self, id: &str) -> Result<bool, MailError> {
        let _guard = write_lock(&self.lock);
        let mut drafts = self.read_drafts_unlocked();
        let before = drafts.len();
        drafts.retain(|d| d.id != id);
        if drafts.len() < before {
            self.write_drafts_unlocked(&drafts)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn record_sent_message(
        &self,
        req: &SendEmailRequest,
        message_id_header: String,
    ) -> Result<MailMessage, MailError> {
        let username = self.username();
        let msg = build_sent_message(&self.account_address(), &username, req, message_id_header)?;
        let _guard = write_lock(&self.lock);
        let mut messages = self.read_messages_unlocked();
        messages.insert(0, msg.clone());
        self.write_messages_unlocked(&messages)?;
        Ok(msg)
    }

    fn folder_counts(&self) -> Result<Vec<MailFolderCount>, MailError> {
        let _guard = read_lock(&self.lock);
        Ok(compute_folder_counts(&self.read_messages_unlocked()))
    }
}

fn normalize_username(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches("@proxy.ing")
        .trim_end_matches(".proxy.ing")
        .to_string();
    if trimmed.is_empty() {
        "proxy".to_string()
    } else {
        trimmed
    }
}

fn resolve_domain_username(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let entries: Vec<Value> = serde_json::from_slice(&bytes).ok()?;
    entries
        .iter()
        .filter(|entry| entry.get("isEnabled").and_then(Value::as_bool) == Some(true))
        .find_map(|entry| entry.get("username").and_then(Value::as_str))
        .map(normalize_username)
}

fn write_json_atomic<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), MailError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| MailError::Storage(e.to_string()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| MailError::Storage(e.to_string()))?;
    let tmp = path.with_extension(format!("tmp-{}", random_hex_id()));
    std::fs::write(&tmp, bytes).map_err(|e| MailError::Storage(e.to_string()))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(MailError::Storage(e.to_string()));
    }
    Ok(())
}

fn build_inbound_message(
    account_address: &str,
    payload: InboundEmailPayload,
) -> Result<MailMessage, MailError> {
    let parsed = payload
        .raw_rfc5322_base64
        .as_deref()
        .and_then(|b64| STANDARD.decode(b64.trim()).ok())
        .map(|raw| parse_raw_rfc5322(&raw));

    let from = non_empty(Some(payload.sender))
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|p| non_empty(Some(p.from.clone())))
        })
        .ok_or_else(|| MailError::InvalidInput("missing sender address".to_string()))?;

    let from_name = non_empty(payload.sender_name)
        .or_else(|| parsed.as_ref().and_then(|p| p.from_name.clone()));

    let to = payload
        .to
        .filter(|v| !v.is_empty())
        .or_else(|| {
            parsed
                .as_ref()
                .map(|p| p.to.clone())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| {
            let rec =
                non_empty(Some(payload.recipient)).unwrap_or_else(|| account_address.to_string());
            vec![rec]
        });

    let cc = payload
        .cc
        .or_else(|| parsed.as_ref().map(|p| p.cc.clone()))
        .unwrap_or_default();

    let reply_to =
        non_empty(payload.reply_to).or_else(|| parsed.as_ref().and_then(|p| p.reply_to.clone()));

    let subject = non_empty(payload.subject)
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|p| non_empty(Some(p.subject.clone())))
        })
        .unwrap_or_else(|| "(no subject)".to_string());

    let text_body = non_empty(payload.text_body)
        .or_else(|| parsed.as_ref().map(|p| p.text_body.clone()))
        .unwrap_or_default();

    let html_body =
        non_empty(payload.html_body).or_else(|| parsed.as_ref().and_then(|p| p.html_body.clone()));

    let id = non_empty(payload.id).unwrap_or_else(|| format!("msg-{}", random_hex_id()));
    let message_id_header = non_empty(payload.message_id_header)
        .or_else(|| parsed.as_ref().and_then(|p| p.message_id.clone()))
        .unwrap_or_else(|| format!("<{id}@proxy.ing>"));

    let in_reply_to = non_empty(payload.in_reply_to)
        .or_else(|| parsed.as_ref().and_then(|p| p.in_reply_to.clone()));

    let references = payload
        .references
        .or_else(|| parsed.as_ref().map(|p| p.references.clone()))
        .unwrap_or_default();

    let thread_id = in_reply_to
        .as_deref()
        .or_else(|| references.first().map(String::as_str))
        .map(clean_msg_id)
        .unwrap_or_else(|| clean_msg_id(&message_id_header));

    let attachments = payload
        .attachments
        .or_else(|| parsed.map(|p| p.attachments))
        .unwrap_or_default();

    let snippet = make_snippet(&text_body);
    let received_at = non_empty(payload.received_at).unwrap_or_else(now_iso8601);

    Ok(MailMessage {
        id,
        thread_id,
        account_address: account_address.to_string(),
        folder: "inbox".to_string(),
        from,
        from_name,
        to,
        cc,
        reply_to,
        subject,
        snippet,
        text_body,
        html_body,
        message_id_header,
        in_reply_to,
        references,
        unread: true,
        starred: false,
        spf_status: payload.spf_status.or_else(|| Some("pass".to_string())),
        dkim_status: payload.dkim_status.or_else(|| Some("pass".to_string())),
        dmarc_status: payload.dmarc_status.or_else(|| Some("pass".to_string())),
        received_at,
        attachments,
    })
}

fn build_sent_message(
    account_address: &str,
    username: &str,
    req: &SendEmailRequest,
    message_id_header: String,
) -> Result<MailMessage, MailError> {
    if req.to.is_empty() {
        return Err(MailError::InvalidInput(
            "at least one recipient in 'to' is required".to_string(),
        ));
    }
    let id = format!("msg-{}", random_hex_id());
    let from_name = req
        .from_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| Some(humanize_slug(username)));
    let references = req.references.clone().unwrap_or_default();
    let thread_id = req
        .in_reply_to
        .as_deref()
        .or_else(|| references.first().map(String::as_str))
        .map(clean_msg_id)
        .unwrap_or_else(|| clean_msg_id(&message_id_header));
    let subject = if req.subject.trim().is_empty() {
        "(no subject)".to_string()
    } else {
        req.subject.trim().to_string()
    };
    Ok(MailMessage {
        id,
        thread_id,
        account_address: account_address.to_string(),
        folder: "sent".to_string(),
        from: account_address.to_string(),
        from_name,
        to: req.to.clone(),
        cc: req.cc.clone().unwrap_or_default(),
        reply_to: req.reply_to.clone(),
        subject,
        snippet: make_snippet(&req.text_body),
        text_body: req.text_body.clone(),
        html_body: req.html_body.clone(),
        message_id_header,
        in_reply_to: req.in_reply_to.clone(),
        references,
        unread: false,
        starred: false,
        spf_status: Some("pass".to_string()),
        dkim_status: Some("pass".to_string()),
        dmarc_status: Some("pass".to_string()),
        received_at: now_iso8601(),
        attachments: Vec::new(),
    })
}

fn apply_patch(msg: &mut MailMessage, patch: MailMessagePatch) -> Result<(), MailError> {
    if let Some(unread) = patch.unread {
        msg.unread = unread;
    }
    if let Some(starred) = patch.starred {
        msg.starred = starred;
    }
    if let Some(folder) = patch.folder {
        let clean = folder.trim().to_ascii_lowercase();
        if !MAIL_FOLDERS.contains(&clean.as_str()) {
            return Err(MailError::InvalidInput(format!(
                "unsupported folder '{clean}' (expected inbox, sent, archive, or trash)"
            )));
        }
        msg.folder = clean;
    }
    Ok(())
}

fn filter_messages(
    messages: &[MailMessage],
    folder: Option<&str>,
    query: Option<&str>,
    unread_only: bool,
    limit: usize,
) -> Vec<MailMessage> {
    let folder_filter = folder
        .map(|f| f.trim().to_ascii_lowercase())
        .filter(|f| !f.is_empty());
    let query_filter = query
        .map(|q| q.trim().to_ascii_lowercase())
        .filter(|q| !q.is_empty());
    let cap = limit.clamp(1, 500);

    messages
        .iter()
        .filter(|m| {
            if let Some(f) = &folder_filter {
                if f == "starred" {
                    if !m.starred {
                        return false;
                    }
                } else if m.folder != *f {
                    return false;
                }
            }
            if unread_only && !m.unread {
                return false;
            }
            if let Some(q) = &query_filter {
                let hay = format!(
                    "{} {} {} {} {}",
                    m.subject,
                    m.from,
                    m.from_name.as_deref().unwrap_or(""),
                    m.text_body,
                    m.to.join(" ")
                )
                .to_ascii_lowercase();
                if !hay.contains(q) {
                    return false;
                }
            }
            true
        })
        .take(cap)
        .cloned()
        .collect()
}

fn compute_folder_counts(messages: &[MailMessage]) -> Vec<MailFolderCount> {
    MAIL_FOLDERS
        .iter()
        .map(|folder| {
            let mut total = 0;
            let mut unread = 0;
            for m in messages {
                if m.folder == *folder {
                    total += 1;
                    if m.unread {
                        unread += 1;
                    }
                }
            }
            MailFolderCount {
                folder: (*folder).to_string(),
                total,
                unread,
            }
        })
        .collect()
}

fn non_empty(val: Option<String>) -> Option<String> {
    val.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn clean_msg_id(raw: &str) -> String {
    raw.trim().trim_matches(['<', '>']).to_string()
}

fn make_snippet(body: &str) -> String {
    body.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect()
}

pub(crate) fn random_hex_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub(crate) fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}Z")
}
