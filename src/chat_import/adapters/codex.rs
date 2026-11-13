//! OpenAI Codex CLI `~/.codex/sessions/**/*.jsonl` (`response_item` / `event_msg`) adapter.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    CODEX_MESH_SPEC, CODEX_PROVIDERS, mesh_load_conversations, mesh_resolve_source,
    mesh_scan_manifests,
};
use crate::chat_import::{
    CODEX_ADAPTER_ID, ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind,
    ConversationManifest, ImportedConversation, ImportedTurn, collect_files_bounded,
    extract_value_text, fallback_title, file_mtime_secs, normalize_role, parse_timestamp_secs,
    preview_from_turns, stable_hash_hex, user_home_dir,
};

pub struct CodexAdapter;

impl ChatImportAdapter for CodexAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: CODEX_ADAPTER_ID.to_string(),
            display_name: "Codex".to_string(),
            subtitle: "Local or mesh-synced OpenAI Codex CLI sessions (~/.codex/sessions)"
                .to_string(),
            export_hint:
                "Automatically discovered from ~/.codex/sessions and mesh-synced proxy.db threads"
                    .to_string(),
            icon_name: "chevron.left.forwardslash.chevron.right".to_string(),
            source_kind: ChatImportSourceKind::LocalStore.into(),
            extensions: vec!["jsonl".to_string()],
            brand_id: "codex".to_string(),
            default_agent_id: "gpt".to_string(),
        }
    }

    fn default_local_path(&self, _data_root: Option<&Path>) -> Option<PathBuf> {
        user_home_dir().map(|home| home.join(".codex").join("sessions"))
    }

    fn resolve_source(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
    ) -> Result<(Option<String>, bool), String> {
        mesh_resolve_source(
            custom_path,
            self.default_local_path(data_root),
            data_root,
            CODEX_PROVIDERS,
        )
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        let path_str = path.to_string_lossy();
        if path.is_dir() {
            return u8::from(path_str.contains(".codex") || path.join("sessions").is_dir()) * 92;
        }
        if !path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        {
            return 0;
        }
        let text = String::from_utf8_lossy(head);
        if text.contains("\"session_meta\"")
            || text.contains("\"response_item\"")
            || text.contains("\"event_msg\"")
        {
            return 96;
        }
        u8::from(path_str.contains(".codex")) * 90
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        parse_codex_path(path, None)
    }

    fn scan_manifests(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
    ) -> Result<Vec<ConversationManifest>, String> {
        mesh_scan_manifests(
            custom_path,
            self.default_local_path(data_root),
            data_root,
            CODEX_PROVIDERS,
            &CODEX_MESH_SPEC,
            scan_codex_path,
        )
    }

    fn load_conversations(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
        selected_ids: Option<&HashSet<String>>,
    ) -> Result<Vec<ImportedConversation>, String> {
        mesh_load_conversations(
            custom_path,
            self.default_local_path(data_root),
            data_root,
            CODEX_PROVIDERS,
            &CODEX_MESH_SPEC,
            selected_ids,
            parse_codex_path,
        )
    }
}

fn scan_codex_path(path: &Path) -> Result<Vec<ConversationManifest>, String> {
    if path.is_dir() {
        let files = list_codex_files(path)?;
        let mut seen_ids = HashSet::new();
        let mut out = Vec::new();
        for f in files {
            if let Ok(Some(m)) = scan_codex_manifest(&f)
                && seen_ids.insert(m.source_id.clone())
            {
                out.push(m);
            }
        }
        return Ok(out);
    }
    Ok(scan_codex_manifest(path)?.into_iter().collect())
}

fn parse_codex_path(
    path: &Path,
    _selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    if path.is_dir() {
        let files = list_codex_files(path)?;
        let mut seen_ids = HashSet::new();
        let mut out = Vec::new();
        for f in files {
            if let Ok(convs) = parse_codex_jsonl(&f) {
                for conv in convs {
                    if seen_ids.insert(conv.source_id.clone()) {
                        out.push(conv);
                    }
                }
            }
        }
        return Ok(out);
    }
    parse_codex_jsonl(path)
}

fn list_codex_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let scan_root = if path.join("sessions").is_dir() {
        path.join("sessions")
    } else {
        path.to_path_buf()
    };
    let mut files = Vec::new();
    collect_files_bounded(&scan_root, 6, &mut files)?;
    files.retain(|f| {
        f.extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
    });
    Ok(files)
}

fn is_relevant_codex_line(line: &str) -> bool {
    if line.contains("\"function_call_output\"") || line.contains("\"function_call\"") {
        return false;
    }
    line.contains("\"session_meta\"")
        || line.contains("\"user_message\"")
        || line.contains("\"agent_message\"")
        || line.contains("\"item_completed\"")
        || (line.contains("\"response_item\"") && line.contains("\"message\""))
}

fn scan_codex_manifest(path: &Path) -> Result<Option<ConversationManifest>, String> {
    let fallback_ts = file_mtime_secs(path);
    let file = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let (mut session_id, mut first_ts, mut last_ts) = (None, None, fallback_ts);
    let (mut msg_count, mut user_count, mut asst_count) = (0_usize, 0_usize, 0_usize);
    let mut seen_ids = HashSet::new();
    let mut last_sig: Option<(String, usize)> = None;
    let mut sample_turns: Vec<ImportedTurn> = Vec::new();

    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|e| format!("reading {}: {e}", path.display()))?
            == 0
        {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || !is_relevant_codex_line(trimmed) {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let ts = parse_timestamp_secs(record.get("timestamp")).unwrap_or(fallback_ts);
        let rec_type = record
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload = record.get("payload").unwrap_or(&record);

        if rec_type == "session_meta" {
            session_id = session_id.or_else(|| {
                payload
                    .get("session_id")
                    .or_else(|| payload.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            first_ts.get_or_insert(ts);
            continue;
        }
        let Some((item_id, role, content)) = extract_codex_turn(rec_type, payload) else {
            continue;
        };
        if is_codex_boilerplate(&content) || item_id.is_some_and(|id| !seen_ids.insert(id)) {
            continue;
        }
        let content_len = content.trim().len();
        if last_sig
            .as_ref()
            .is_some_and(|(r, len)| r == &role && *len == content_len)
        {
            continue;
        }
        last_sig = Some((role.clone(), content_len));
        first_ts.get_or_insert(ts);
        last_ts = last_ts.max(ts);
        msg_count += 1;
        if role == "user" {
            user_count += 1;
        } else if role == "assistant" {
            asst_count += 1;
        }
        if sample_turns.len() < 2 {
            sample_turns.push(ImportedTurn {
                role,
                content,
                timestamp: ts,
            });
        }
    }
    if msg_count == 0 {
        return Ok(None);
    }
    let sid = session_id
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| stable_hash_hex(&path.to_string_lossy()));
    let created_at = first_ts.unwrap_or(fallback_ts);
    Ok(Some(ConversationManifest {
        source_id: format!("codex:{sid}"),
        adapter_id: CODEX_ADAPTER_ID.to_string(),
        title: fallback_title(None, &sample_turns, "Codex Session"),
        scope: "owner".to_string(),
        message_count: msg_count,
        user_message_count: user_count,
        assistant_message_count: asst_count,
        created_at,
        updated_at: last_ts.max(created_at),
        preview: preview_from_turns(&sample_turns),
        participants: vec!["user".to_string(), "Codex".to_string()],
    }))
}

fn parse_codex_jsonl(path: &Path) -> Result<Vec<ImportedConversation>, String> {
    let fallback_ts = file_mtime_secs(path);
    let file = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let (mut session_id, mut first_ts, mut last_ts) = (None, None, fallback_ts);
    let (mut turns, mut seen_ids) = (Vec::<ImportedTurn>::new(), HashSet::new());

    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|e| format!("reading {}: {e}", path.display()))?
            == 0
        {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || !is_relevant_codex_line(trimmed) {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let ts = parse_timestamp_secs(record.get("timestamp")).unwrap_or(fallback_ts);
        let rec_type = record
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload = record.get("payload").unwrap_or(&record);

        if rec_type == "session_meta" {
            session_id = session_id.or_else(|| {
                payload
                    .get("session_id")
                    .or_else(|| payload.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            first_ts.get_or_insert(ts);
            continue;
        }
        let Some((item_id, role, content)) = extract_codex_turn(rec_type, payload) else {
            continue;
        };
        if is_codex_boilerplate(&content) {
            continue;
        }
        if item_id.is_some_and(|id| !seen_ids.insert(id)) {
            continue;
        }
        if turns
            .last()
            .is_some_and(|p| p.role == role && p.content.trim() == content.trim())
        {
            continue;
        }
        first_ts.get_or_insert(ts);
        last_ts = last_ts.max(ts);
        turns.push(ImportedTurn {
            role,
            content,
            timestamp: ts,
        });
    }
    if turns.is_empty() {
        return Ok(Vec::new());
    }
    let sid = session_id
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| stable_hash_hex(&path.to_string_lossy()));

    Ok(vec![ImportedConversation::from_turns(
        format!("codex:{sid}"),
        CODEX_ADAPTER_ID,
        None,
        "Codex Session",
        "owner".to_string(),
        first_ts.unwrap_or(fallback_ts),
        last_ts,
        vec!["user".to_string(), "Codex".to_string()],
        turns,
    )])
}

fn extract_codex_turn(rec_type: &str, payload: &Value) -> Option<(Option<String>, String, String)> {
    match rec_type {
        "response_item" => {
            if payload
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("message")
                != "message"
            {
                return None;
            }
            let raw_role = payload
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user");
            if raw_role == "developer" || raw_role == "system" {
                return None;
            }
            let content = payload
                .get("content")
                .map(extract_value_text)
                .unwrap_or_default();
            let id = payload
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string);
            (!content.trim().is_empty()).then(|| (id, normalize_role(raw_role), content))
        }
        "event_msg" => {
            let ptype = payload
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if ptype == "user_message" || ptype == "agent_message" {
                let role = if ptype == "user_message" {
                    "user"
                } else {
                    "assistant"
                };
                let content = payload
                    .get("message")
                    .or_else(|| payload.get("text"))
                    .or_else(|| payload.get("content"))
                    .map(extract_value_text)
                    .unwrap_or_default();
                let id = payload
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                return (!content.trim().is_empty()).then(|| (id, role.to_string(), content));
            }
            if ptype == "item_completed" {
                let item = payload.get("item")?;
                let role = match item.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "UserMessage" | "user_message" => "user",
                    "AgentMessage" | "agent_message" | "AssistantMessage" => "assistant",
                    _ => return None,
                };
                let content = item
                    .get("content")
                    .or_else(|| item.get("text"))
                    .map(extract_value_text)
                    .unwrap_or_default();
                let id = item.get("id").and_then(Value::as_str).map(str::to_string);
                return (!content.trim().is_empty()).then(|| (id, role.to_string(), content));
            }
            None
        }
        _ => None,
    }
}

fn is_codex_boilerplate(text: &str) -> bool {
    let t = text.trim();
    t.starts_with("<environment_context>")
        || t.starts_with("<skills_instructions>")
        || t.starts_with("<multi_agent_role>")
        || t.starts_with("<multi_agent_mode>")
}
