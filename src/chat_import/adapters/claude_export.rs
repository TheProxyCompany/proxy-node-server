//! Anthropic Claude web and desktop export (`conversations.json` / `.zip`) adapter.

use std::fs;
use std::path::Path;

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
                "Claude -> Settings -> Privacy -> Export Data (.zip or conversations.json)"
                    .to_string(),
            icon_name: "sparkles".to_string(),
            source_kind: ChatImportSourceKind::ExportFile.into(),
            extensions: vec!["zip".to_string(), "json".to_string()],
        }
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        if path.is_dir() {
            let conv = path.join("conversations.json");
            return if conv.is_file() {
                self.sniff(&conv, &read_sniff_head(&conv).unwrap_or_default())
            } else {
                0
            };
        }
        if head.starts_with(b"PK\x03\x04") {
            let Some(entries) = fs::read(path)
                .ok()
                .and_then(|b| read_zip_entries(&b, is_conv_name).ok())
            else {
                return 0;
            };
            return u8::from(entries.iter().any(|(_, p)| {
                let s = String::from_utf8_lossy(&p[..p.len().min(16_384)]);
                s.contains("\"chat_messages\"") && s.contains("\"sender\"")
            })) * 96;
        }
        let text = String::from_utf8_lossy(head);
        if text.contains("\"chat_messages\"") && text.contains("\"sender\"") {
            return 95;
        }
        0
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        let fallback_ts = file_mtime_secs(path);
        let target = if path.is_dir() {
            path.join("conversations.json")
        } else {
            path.to_path_buf()
        };
        let raw = fs::read(&target).map_err(|e| format!("reading {}: {e}", target.display()))?;
        if raw.starts_with(b"PK\x03\x04") {
            let mut out = Vec::new();
            for (_, payload) in read_zip_entries(&raw, is_conv_name)? {
                out.extend(parse_anthropic_json(&payload, fallback_ts)?);
            }
            return Ok(out);
        }
        parse_anthropic_json(&raw, fallback_ts)
    }
}

fn is_conv_name(name: &str) -> bool {
    name == "conversations.json" || name.ends_with("/conversations.json")
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
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_else(|| vec![&root]),
        _ => Vec::new(),
    };

    let mut out = Vec::new();
    for conv in items {
        let Some(msgs) = conv.get("chat_messages").and_then(Value::as_array) else {
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
