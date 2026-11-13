//! OpenAI ChatGPT `conversations.json` (mapping graph or messages array) and `.zip` archive adapter.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

use super::read_zip_entries;
use crate::chat_import::{
    CHATGPT_ADAPTER_ID, ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind,
    ImportedConversation, ImportedTurn, extract_value_text, file_mtime_secs, normalize_role,
    parse_timestamp_secs, read_sniff_head, stable_hash_hex,
};

pub struct ChatGptAdapter;

impl ChatImportAdapter for ChatGptAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: CHATGPT_ADAPTER_ID.to_string(),
            display_name: "ChatGPT".to_string(),
            subtitle: "OpenAI ChatGPT data export archive or conversations.json".to_string(),
            export_hint:
                "ChatGPT -> Settings -> Data Controls -> Export Data (.zip or conversations.json)"
                    .to_string(),
            icon_name: "bubble.left.and.bubble.right".to_string(),
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
            let Ok(bytes) = fs::read(path) else {
                return 0;
            };
            let Ok(entries) = read_zip_entries(&bytes, is_conv_json_name) else {
                return 0;
            };
            let matched = entries.iter().any(|(_, p)| {
                let s = String::from_utf8_lossy(&p[..p.len().min(16_384)]);
                s.contains("\"mapping\"") || s.contains("\"current_node\"")
            });
            return if matched { 96 } else { 0 };
        }
        let text = String::from_utf8_lossy(head);
        if text.contains("\"mapping\"")
            && (text.contains("\"current_node\"") || text.contains("\"author\""))
        {
            return 95;
        }
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if fname.eq_ignore_ascii_case("conversations.json")
            && text.contains("\"conversation_id\"")
            && text.contains("\"create_time\"")
        {
            return 85;
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
            for (_, payload) in read_zip_entries(&raw, is_conv_json_name)? {
                out.extend(parse_conversations_bytes(&payload, fallback_ts)?);
            }
            return Ok(out);
        }
        parse_conversations_bytes(&raw, fallback_ts)
    }
}

fn is_conv_json_name(name: &str) -> bool {
    name == "conversations.json"
        || name.ends_with("/conversations.json")
        || (name.contains("conversations-") && name.ends_with(".json"))
}

fn parse_conversations_bytes(
    bytes: &[u8],
    fallback_ts: u64,
) -> Result<Vec<ImportedConversation>, String> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parsing ChatGPT JSON: {e}"))?;
    let items: Vec<&Value> = match &root {
        Value::Array(arr) => arr.iter().collect(),
        Value::Object(map) => map
            .get("conversations")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_else(|| vec![&root]),
        _ => Vec::new(),
    };
    Ok(items
        .into_iter()
        .filter_map(|item| parse_single_conversation(item, fallback_ts))
        .collect())
}

fn parse_single_conversation(conv: &Value, fallback_ts: u64) -> Option<ImportedConversation> {
    let created_at = parse_timestamp_secs(conv.get("create_time")).unwrap_or(fallback_ts);
    let updated_at = parse_timestamp_secs(conv.get("update_time")).unwrap_or(created_at);
    let turns = if let Some(mapping) = conv.get("mapping").and_then(Value::as_object) {
        extract_mapping_turns(
            mapping,
            conv.get("current_node").and_then(Value::as_str),
            created_at,
        )
    } else if let Some(msgs) = conv.get("messages").and_then(Value::as_array) {
        msgs.iter()
            .filter_map(|m| extract_msg_turn(m, created_at))
            .collect()
    } else {
        Vec::new()
    };
    if turns.is_empty() {
        return None;
    }
    let raw_id = conv
        .get("conversation_id")
        .or_else(|| conv.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let source_id = match raw_id {
        Some(id) => format!("chatgpt:{id}"),
        None => format!(
            "chatgpt:{}",
            stable_hash_hex(&format!(
                "{}:{}:{}",
                conv.get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                created_at,
                turns[0].content
            ))
        ),
    };
    Some(ImportedConversation::from_turns(
        source_id,
        CHATGPT_ADAPTER_ID,
        conv.get("title").and_then(Value::as_str),
        "ChatGPT Conversation",
        "owner".to_string(),
        created_at,
        updated_at,
        vec!["user".to_string(), "ChatGPT".to_string()],
        turns,
    ))
}

fn extract_mapping_turns(
    mapping: &serde_json::Map<String, Value>,
    current_node: Option<&str>,
    default_ts: u64,
) -> Vec<ImportedTurn> {
    let ordered_ids = if let Some(leaf) = current_node.filter(|id| mapping.contains_key(*id)) {
        let (mut chain, mut seen, mut cur) = (Vec::new(), HashSet::new(), Some(leaf));
        while let Some(id) = cur {
            if !seen.insert(id) {
                break;
            }
            chain.push(id.to_string());
            cur = mapping
                .get(id)
                .and_then(|n| n.get("parent"))
                .and_then(Value::as_str);
        }
        chain.reverse();
        chain
    } else {
        let mut ids: Vec<String> = mapping.keys().cloned().collect();
        ids.sort_by_key(|k| {
            mapping
                .get(k)
                .and_then(|n| n.get("message"))
                .and_then(|m| parse_timestamp_secs(m.get("create_time")))
                .unwrap_or(default_ts)
        });
        ids
    };
    ordered_ids
        .into_iter()
        .filter_map(|id| mapping.get(&id).and_then(|n| n.get("message")))
        .filter(|m| !m.is_null())
        .filter_map(|m| extract_msg_turn(m, default_ts))
        .collect()
}

fn extract_msg_turn(msg: &Value, default_ts: u64) -> Option<ImportedTurn> {
    if msg
        .pointer("/metadata/is_visually_hidden_from_conversation")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return None;
    }
    let role_raw = msg
        .pointer("/author/role")
        .or_else(|| msg.get("role"))
        .and_then(Value::as_str)
        .unwrap_or("user");
    let role = normalize_role(role_raw);
    if role == "system" {
        return None;
    }
    let content = msg
        .get("content")
        .map(extract_value_text)
        .unwrap_or_default();
    if content.trim().is_empty() {
        return None;
    }
    let timestamp = parse_timestamp_secs(msg.get("create_time").or_else(|| msg.get("timestamp")))
        .unwrap_or(default_ts);
    Some(ImportedTurn {
        role,
        content,
        timestamp,
    })
}
