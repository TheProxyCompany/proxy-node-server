//! Anthropic Claude Code CLI `~/.claude/projects/**/*.jsonl` local session store adapter.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::claude_export::extract_claude_msg_text;
use super::{
    CLAUDE_CODE_MESH_SPEC, CLAUDE_CODE_PROVIDERS, mesh_load_conversations, mesh_resolve_source,
    mesh_scan_manifests,
};
use crate::chat_import::{
    CLAUDE_CODE_ADAPTER_ID, ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind,
    ConversationManifest, ImportedConversation, ImportedTurn, collect_files_bounded,
    fallback_title, file_mtime_secs, normalize_role, parse_timestamp_secs, preview_from_turns,
    stable_hash_hex, user_home_dir,
};

pub struct ClaudeCodeAdapter;

impl ChatImportAdapter for ClaudeCodeAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: CLAUDE_CODE_ADAPTER_ID.to_string(),
            display_name: "Claude Code".to_string(),
            subtitle: "Local or mesh-synced Claude Code CLI transcripts (~/.claude/projects)"
                .to_string(),
            export_hint:
                "Automatically discovered from ~/.claude/projects and mesh-synced proxy.db threads"
                    .to_string(),
            icon_name: "terminal".to_string(),
            source_kind: ChatImportSourceKind::LocalStore.into(),
            extensions: vec!["jsonl".to_string()],
            brand_id: "claude_code".to_string(),
            default_agent_id: "claude".to_string(),
        }
    }

    fn default_local_path(&self, _data_root: Option<&Path>) -> Option<PathBuf> {
        user_home_dir().map(|home| home.join(".claude").join("projects"))
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
            CLAUDE_CODE_PROVIDERS,
        )
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        let path_str = path.to_string_lossy();
        if path.is_dir() {
            if path.join("conversations.json").is_file() {
                return 0;
            }
            return u8::from(path_str.contains(".claude") || path.join("projects").is_dir()) * 92;
        }
        if !path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        {
            return 0;
        }
        if path_str.contains(".claude") {
            return 94;
        }
        let text = String::from_utf8_lossy(head);
        let has_meta = text.contains("\"sessionId\"") || text.contains("\"parentUuid\"");
        let has_user = text.contains("\"type\":\"user\"") || text.contains("\"type\": \"user\"");
        if has_meta && text.contains("\"message\"") && has_user {
            return 90;
        }
        0
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        parse_claude_code_path(path, None)
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
            CLAUDE_CODE_PROVIDERS,
            &CLAUDE_CODE_MESH_SPEC,
            scan_claude_code_path,
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
            CLAUDE_CODE_PROVIDERS,
            &CLAUDE_CODE_MESH_SPEC,
            selected_ids,
            parse_claude_code_path,
        )
    }
}

fn scan_claude_code_path(path: &Path) -> Result<Vec<ConversationManifest>, String> {
    if path.is_dir() {
        let files = list_jsonl_files(path)?;
        let mut seen_ids = HashSet::new();
        let mut out = Vec::new();
        for f in files {
            if let Ok(Some(m)) = scan_claude_code_manifest(&f)
                && seen_ids.insert(m.source_id.clone())
            {
                out.push(m);
            }
        }
        return Ok(out);
    }
    Ok(scan_claude_code_manifest(path)?.into_iter().collect())
}

fn parse_claude_code_path(
    path: &Path,
    selected_ids: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    if path.is_dir() {
        let files = list_jsonl_files(path)?;
        let mut seen_ids = HashSet::new();
        let mut out = Vec::new();
        for f in files {
            if let Some(sel) = selected_ids
                && let Some(stem) = f.file_stem().and_then(|s| s.to_str())
                && !sel.contains(&format!("claude_code:{stem}"))
                && file_head_has_matching_session(&f, stem)
            {
                continue;
            }
            if let Ok(convs) = parse_claude_code_jsonl(&f) {
                for conv in convs {
                    if selected_ids.is_none_or(|sel| sel.contains(&conv.source_id))
                        && seen_ids.insert(conv.source_id.clone())
                    {
                        out.push(conv);
                    }
                }
            }
        }
        return Ok(out);
    }
    parse_claude_code_jsonl(path)
}

fn list_jsonl_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let scan_root = if path.join("projects").is_dir() {
        path.join("projects")
    } else {
        path.to_path_buf()
    };
    let mut files = Vec::new();
    collect_files_bounded(&scan_root, 5, &mut files)?;
    files.retain(|f| {
        f.extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
    });
    Ok(files)
}

fn file_head_has_matching_session(path: &Path, stem: &str) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let needle = format!("\"sessionId\":\"{stem}\"");
    let needle_sp = format!("\"sessionId\": \"{stem}\"");
    for _ in 0..3 {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line.contains(&needle) || line.contains(&needle_sp) {
            return true;
        }
    }
    false
}

fn is_relevant_claude_line(line: &str) -> bool {
    line.contains("\"user\"") || line.contains("\"assistant\"") || line.contains("\"summary\"")
}

fn scan_claude_code_manifest(path: &Path) -> Result<Option<ConversationManifest>, String> {
    let fallback_ts = file_mtime_secs(path);
    let file = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let (mut session_id, mut summary_title, mut first_ts, mut last_ts) =
        (None, None, None, fallback_ts);
    let (mut msg_count, mut user_count, mut asst_count) = (0_usize, 0_usize, 0_usize);
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
        if trimmed.is_empty() || !is_relevant_claude_line(trimmed) {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if session_id.is_none() {
            session_id = val
                .get("sessionId")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        let kind = val.get("type").and_then(Value::as_str).unwrap_or_default();
        if kind == "summary" && summary_title.is_none() {
            summary_title = val
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string);
        } else if kind == "user" || kind == "assistant" {
            let content = extract_claude_msg_text(val.get("message").unwrap_or(&val));
            if !content.trim().is_empty() {
                let ts = parse_timestamp_secs(val.get("timestamp")).unwrap_or(fallback_ts);
                first_ts.get_or_insert(ts);
                last_ts = last_ts.max(ts);
                let role = normalize_role(kind);
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
        }
    }
    if msg_count == 0 {
        return Ok(None);
    }
    let sid = session_id
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| stable_hash_hex(&path.to_string_lossy()));
    let created_at = first_ts.unwrap_or(fallback_ts);
    Ok(Some(ConversationManifest {
        source_id: format!("claude_code:{sid}"),
        adapter_id: CLAUDE_CODE_ADAPTER_ID.to_string(),
        title: fallback_title(
            summary_title.as_deref(),
            &sample_turns,
            "Claude Code Session",
        ),
        scope: "owner".to_string(),
        message_count: msg_count,
        user_message_count: user_count,
        assistant_message_count: asst_count,
        created_at,
        updated_at: last_ts.max(created_at),
        preview: preview_from_turns(&sample_turns),
        participants: vec!["user".to_string(), "Claude Code".to_string()],
    }))
}

fn parse_claude_code_jsonl(path: &Path) -> Result<Vec<ImportedConversation>, String> {
    let fallback_ts = file_mtime_secs(path);
    let file = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let (mut session_id, mut summary_title, mut first_ts, mut last_ts) =
        (None, None, None, fallback_ts);
    let mut turns = Vec::new();

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
        if trimmed.is_empty() || !is_relevant_claude_line(trimmed) {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if session_id.is_none() {
            session_id = val
                .get("sessionId")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        let kind = val.get("type").and_then(Value::as_str).unwrap_or_default();
        if kind == "summary" && summary_title.is_none() {
            summary_title = val
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string);
        } else if kind == "user" || kind == "assistant" {
            let content = extract_claude_msg_text(val.get("message").unwrap_or(&val));
            if !content.trim().is_empty() {
                let ts = parse_timestamp_secs(val.get("timestamp")).unwrap_or(fallback_ts);
                first_ts.get_or_insert(ts);
                last_ts = last_ts.max(ts);
                turns.push(ImportedTurn {
                    role: normalize_role(kind),
                    content,
                    timestamp: ts,
                });
            }
        }
    }
    if turns.is_empty() {
        return Ok(Vec::new());
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let sid = session_id
        .or(stem)
        .unwrap_or_else(|| stable_hash_hex(&path.to_string_lossy()));

    Ok(vec![ImportedConversation::from_turns(
        format!("claude_code:{sid}"),
        CLAUDE_CODE_ADAPTER_ID,
        summary_title.as_deref(),
        "Claude Code Session",
        "owner".to_string(),
        first_ts.unwrap_or(fallback_ts),
        last_ts,
        vec!["user".to_string(), "Claude Code".to_string()],
        turns,
    )])
}
