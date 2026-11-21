//! Anthropic Claude web and desktop export (`conversations.json`, `projects.json`, `projects/*.json`, `.zip`) adapter.
//!
//! A Claude Project becomes one conversation: a turn is `user` only when the person typed it into
//! Claude in their own voice (`description`, `prompt_template`); uploaded material (`docs[]`)
//! becomes `note` turns so reference documents never write personal preferences.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::read_zip_entries;
use crate::chat_import::{
    CLAUDE_EXPORT_ADAPTER_ID, ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind,
    ImportedConversation, ImportedTurn, extract_value_text, file_mtime_secs, normalize_role,
    parse_timestamp_secs, read_sniff_head, stable_hash_hex,
};

pub struct ClaudeExportAdapter;

impl ChatImportAdapter for ClaudeExportAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: CLAUDE_EXPORT_ADAPTER_ID.to_string(),
            display_name: "Claude".to_string(),
            subtitle: "Anthropic Claude web or desktop data export".to_string(),
            export_hint:
                "Claude -> Settings -> Privacy -> Export Data (.zip, export folder, conversations.json or projects.json)"
                    .to_string(),
            icon_name: "sparkles".to_string(),
            source_kind: ChatImportSourceKind::ExportFile.into(),
            extensions: vec!["zip".to_string(), "json".to_string()],
            brand_id: "anthropic".to_string(),
            default_agent_id: "claude".to_string(),
        }
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        if path.is_dir() {
            return export_files_in(path)
                .iter()
                .map(|file| self.sniff(file, &read_sniff_head(file).unwrap_or_default()))
                .max()
                .unwrap_or(0);
        }
        if head.starts_with(b"PK\x03\x04") {
            let Some(entries) = fs::read(path)
                .ok()
                .and_then(|b| read_zip_entries(&b, is_export_name).ok())
            else {
                return 0;
            };
            return u8::from(
                entries
                    .iter()
                    .any(|(name, p)| looks_like_claude_export(name, p)),
            ) * 96;
        }
        let label = entry_label_for_path(path);
        u8::from(looks_like_claude_export(&label, head)) * 95
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        let fallback_ts = file_mtime_secs(path);
        if path.is_dir() {
            let mut matched_any = false;
            let mut out = Vec::new();
            for file in export_files_in(path) {
                let raw =
                    fs::read(&file).map_err(|e| format!("reading {}: {e}", file.display()))?;
                if raw.starts_with(b"PK\x03\x04") {
                    let entries = read_zip_entries(&raw, is_export_name)
                        .map_err(|e| format!("{}: {e}", file.display()))?;
                    if entries.is_empty() {
                        continue;
                    }
                    matched_any = true;
                    for (name, payload) in entries {
                        let parsed = parse_anthropic_json(&payload, fallback_ts)
                            .map_err(|e| format!("{}:{name}: {e}", file.display()))?;
                        out.extend(parsed);
                    }
                } else {
                    matched_any = true;
                    let parsed = parse_anthropic_json(&raw, fallback_ts)
                        .map_err(|e| format!("{}: {e}", file.display()))?;
                    out.extend(parsed);
                }
            }
            if !matched_any {
                return Err(format!(
                    "no conversations.json, projects.json, or Claude export zip in {}",
                    path.display()
                ));
            }
            return Ok(dedupe_conversations(out));
        }
        let raw = fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        if raw.starts_with(b"PK\x03\x04") {
            let entries = read_zip_entries(&raw, is_export_name)?;
            if entries.is_empty() {
                return Err(format!(
                    "no conversations.json, projects.json, or projects/*.json in {}",
                    path.display()
                ));
            }
            let mut out = Vec::new();
            for (name, payload) in entries {
                let parsed = parse_anthropic_json(&payload, fallback_ts)
                    .map_err(|e| format!("{name}: {e}"))?;
                out.extend(parsed);
            }
            return Ok(dedupe_conversations(out));
        }
        parse_anthropic_json(&raw, fallback_ts)
            .map(dedupe_conversations)
            .map_err(|e| format!("{}: {e}", path.display()))
    }
}

const EXPORT_FILE_NAMES: [&str; 2] = ["conversations.json", "projects.json"];

fn export_files_in(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = EXPORT_FILE_NAMES
        .iter()
        .map(|name| dir.join(name))
        .filter(|file| file.is_file())
        .collect();
    out.extend(sorted_dir_files(&dir.join("projects"), ".json"));
    out.extend(
        sorted_dir_files(dir, ".zip")
            .into_iter()
            .filter(|p| is_split_export_zip(p)),
    );
    out
}

fn is_split_export_zip(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            lower.starts_with("conversations-") || lower.starts_with("projects-")
        })
}

fn sorted_dir_files(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    !n.starts_with('.') && n.to_ascii_lowercase().ends_with(suffix)
                })
        })
        .collect();
    files.sort();
    files
}

fn entry_label_for_path(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        == Some("projects")
    {
        format!("projects/{file_name}")
    } else {
        file_name.to_string()
    }
}

fn is_export_name(name: &str) -> bool {
    if name.starts_with("__MACOSX/") || name.contains("/__MACOSX/") {
        return false;
    }
    name == "conversations.json"
        || name.ends_with("/conversations.json")
        || is_project_entry_name(name)
}

fn is_project_entry_name(name: &str) -> bool {
    if name.starts_with("__MACOSX/") || name.contains("/__MACOSX/") {
        return false;
    }
    if name == "projects.json" || name.ends_with("/projects.json") {
        return true;
    }
    let trimmed = name
        .strip_prefix("projects/")
        .or_else(|| name.rsplit_once("/projects/").map(|(_, rest)| rest));
    trimmed.is_some_and(|file| {
        !file.is_empty() && !file.contains('/') && !file.starts_with('.') && file.ends_with(".json")
    })
}

fn looks_like_claude_export(name: &str, head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    let has = |key: &str| text.contains(&format!("\"{key}\""));
    (has("chat_messages") && has("sender"))
        || (has("uuid")
            && (has("prompt_template")
                || has("is_starter_project")
                || (is_project_entry_name(name) && has("description")))
            && (is_project_entry_name(name)
                || has("docs")
                || has("is_private")
                || has("is_starter_project")))
}

fn dedupe_conversations(items: Vec<ImportedConversation>) -> Vec<ImportedConversation> {
    let mut index_by_id: HashMap<String, usize> = HashMap::with_capacity(items.len());
    let mut out: Vec<ImportedConversation> = Vec::with_capacity(items.len());
    for item in items {
        if let Some(&idx) = index_by_id.get(&item.source_id) {
            if item.updated_at > out[idx].updated_at {
                out[idx] = item;
            }
        } else {
            index_by_id.insert(item.source_id.clone(), out.len());
            out.push(item);
        }
    }
    out
}

fn parse_anthropic_json(
    bytes: &[u8],
    fallback_ts: u64,
) -> Result<Vec<ImportedConversation>, String> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parsing Claude export JSON: {e}"))?;
    let items: Vec<&Value> = match &root {
        Value::Array(arr) => arr.iter().collect(),
        Value::Object(map) => map
            .get("conversations")
            .or_else(|| map.get("projects"))
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_else(|| vec![&root]),
        _ => Vec::new(),
    };

    let mut out = Vec::new();
    for conv in items {
        let Some(msgs) = conv.get("chat_messages").and_then(Value::as_array) else {
            out.extend(parse_project(conv, fallback_ts));
            continue;
        };
        let created_at = parse_timestamp_secs(conv.get("created_at")).unwrap_or(fallback_ts);
        let updated_at = parse_timestamp_secs(conv.get("updated_at")).unwrap_or(created_at);
        let turns: Vec<ImportedTurn> = msgs
            .iter()
            .filter_map(|m| {
                let role = normalize_role(
                    m.get("sender")
                        .or_else(|| m.get("role"))
                        .and_then(Value::as_str)
                        .unwrap_or("human"),
                );
                if role == "system" {
                    return None;
                }
                let content = extract_claude_msg_text(m);
                let ts = parse_timestamp_secs(m.get("created_at").or_else(|| m.get("updated_at")))
                    .unwrap_or(created_at);
                (!content.trim().is_empty()).then_some(ImportedTurn {
                    role,
                    content,
                    timestamp: ts,
                })
            })
            .collect();
        if turns.is_empty() {
            continue;
        }
        let raw_id = conv
            .get("uuid")
            .or_else(|| conv.get("id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let source_id = match raw_id {
            Some(id) => format!("claude_export:{id}"),
            None => format!(
                "claude_export:{}",
                stable_hash_hex(&format!("{created_at}:{}", turns[0].content))
            ),
        };
        let raw_name = conv
            .get("name")
            .or_else(|| conv.get("title"))
            .and_then(Value::as_str);
        out.push(ImportedConversation::from_turns(
            source_id,
            CLAUDE_EXPORT_ADAPTER_ID,
            raw_name,
            "Claude Conversation",
            "owner".to_string(),
            created_at,
            updated_at,
            vec!["user".to_string(), "Claude".to_string()],
            turns,
        ));
    }
    Ok(out)
}

fn parse_project(project: &Value, fallback_ts: u64) -> Option<ImportedConversation> {
    if project
        .get("is_starter_project")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    if !project.get("prompt_template").is_some_and(|v| !v.is_null())
        && !project.get("docs").is_some_and(Value::is_array)
    {
        return None;
    }
    fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
    let parsed_created_at = parse_timestamp_secs(project.get("created_at"));
    let created_at = parsed_created_at.unwrap_or(fallback_ts);
    let updated_at = parse_timestamp_secs(project.get("updated_at")).unwrap_or(created_at);
    let turn = |role: &str, label: &str, body: &str, timestamp: u64| ImportedTurn {
        role: role.to_string(),
        content: format!("{label}\n\n{body}"),
        timestamp,
    };

    let mut turns = Vec::new();
    for (key, label) in [
        ("description", "Project description"),
        ("prompt_template", "Project instructions"),
    ] {
        if let Some(body) = text(project, key) {
            turns.push(turn("user", label, body, created_at));
        }
    }
    for doc in project
        .get("docs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(content) = text(doc, "content") else {
            continue;
        };
        let filename = text(doc, "filename").unwrap_or("Untitled");
        let timestamp =
            parse_timestamp_secs(doc.get("created_at").or_else(|| doc.get("updated_at")))
                .unwrap_or(created_at);
        turns.push(turn(
            "note",
            &format!("Project knowledge: {filename}"),
            content,
            timestamp,
        ));
    }
    if turns.is_empty() {
        return None;
    }

    let name = text(project, "name");
    let source_id = match text(project, "uuid") {
        Some(id) => format!("claude_export:project:{id}"),
        None => format!(
            "claude_export:project:{}",
            stable_hash_hex(&format!(
                "{}:{}:{}",
                parsed_created_at.unwrap_or(0),
                name.unwrap_or_default(),
                turns[0].content
            ))
        ),
    };
    Some(ImportedConversation::from_turns(
        source_id,
        CLAUDE_EXPORT_ADAPTER_ID,
        Some(name.unwrap_or("Claude Project")),
        "Claude Project",
        "owner".to_string(),
        created_at,
        updated_at,
        vec!["owner".to_string()],
        turns,
    ))
}

pub(crate) fn extract_claude_msg_text(msg: &Value) -> String {
    if let Some(blocks) = msg.get("content").and_then(Value::as_array) {
        let joined: Vec<String> = blocks
            .iter()
            .filter(|b| {
                b.get("type")
                    .and_then(Value::as_str)
                    .is_none_or(|t| t == "text" || t == "tool_result")
            })
            .map(extract_value_text)
            .filter(|s| !s.is_empty())
            .collect();
        if !joined.is_empty() {
            return joined.join("\n");
        }
    }
    if let Some(s) = msg
        .get("text")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return s.to_string();
    }
    msg.get("content")
        .map(extract_value_text)
        .unwrap_or_default()
}
