//! Generic Markdown notes (`.md` / `.markdown` / `.txt` or directory) and generic `.jsonl` adapter.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::chat_import::{
    ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind, ImportedConversation,
    ImportedTurn, MARKDOWN_JSONL_ADAPTER_ID, collect_files_bounded, extract_value_text,
    file_mtime_secs, normalize_role, parse_timestamp_secs, sanitize_slug, stable_hash_hex,
};

pub struct MarkdownJsonlAdapter;

impl ChatImportAdapter for MarkdownJsonlAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: MARKDOWN_JSONL_ADAPTER_ID.to_string(),
            display_name: "Markdown & JSONL".to_string(),
            subtitle: "Markdown notes, plain text transcripts, or JSONL chat logs".to_string(),
            export_hint: "Select a .md, .txt, or .jsonl file, or a folder of notes".to_string(),
            icon_name: "doc.text".to_string(),
            source_kind: ChatImportSourceKind::ExportFile.into(),
            extensions: vec![
                "md".to_string(),
                "markdown".to_string(),
                "jsonl".to_string(),
                "txt".to_string(),
            ],
            brand_id: "markdown".to_string(),
            default_agent_id: "proxy".to_string(),
        }
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        if path.is_dir() {
            let mut files = Vec::new();
            let _ = collect_files_bounded(path, 3, &mut files);
            return u8::from(files.iter().any(|f| is_note_ext(ext_str(f)))) * 65;
        }
        let ext = ext_str(path);
        if is_note_ext(ext) {
            return 80;
        }
        if ext.eq_ignore_ascii_case("jsonl") {
            let text = String::from_utf8_lossy(head);
            for line in text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(5)
            {
                if let Ok(v) = serde_json::from_str::<Value>(line)
                    && ((v.get("role").is_some() && v.get("content").is_some())
                        || (v.get("kind").is_some() && v.get("text").is_some()))
                {
                    return 75;
                }
            }
        }
        0
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        if path.is_dir() {
            let mut files = Vec::new();
            collect_files_bounded(path, 5, &mut files)?;
            let mut convs = Vec::new();
            for file in files {
                let rel = file
                    .strip_prefix(path)
                    .unwrap_or(&file)
                    .to_string_lossy()
                    .replace('\\', "/");
                if is_note_ext(ext_str(&file)) {
                    convs.extend(parse_markdown_file(&file, Some(&rel))?);
                } else if ext_str(&file).eq_ignore_ascii_case("jsonl") {
                    convs.extend(parse_generic_jsonl_file(&file, Some(&rel))?);
                }
            }
            return Ok(convs);
        }
        if ext_str(path).eq_ignore_ascii_case("jsonl") {
            Ok(parse_generic_jsonl_file(path, None)?.into_iter().collect())
        } else {
            Ok(parse_markdown_file(path, None)?.into_iter().collect())
        }
    }
}

fn ext_str(path: &Path) -> &str {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
}

fn is_note_ext(ext: &str) -> bool {
    matches!(ext.to_ascii_lowercase().as_str(), "md" | "markdown" | "txt")
}

fn parse_markdown_file(
    path: &Path,
    rel_key: Option<&str>,
) -> Result<Option<ImportedConversation>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let ts = file_mtime_secs(path);
    let (fm_title, body) = strip_frontmatter_and_title(raw.trim());
    let turns = parse_markdown_turns(body, ts);
    if turns.is_empty() {
        return Ok(None);
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Markdown Note");
    let h1 = body
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("# ").map(str::trim))
        .filter(|s| !s.is_empty());
    let id_seed =
        rel_key.unwrap_or_else(|| path.file_name().and_then(|s| s.to_str()).unwrap_or(stem));
    let slug = sanitize_slug(id_seed);
    let key = if slug.is_empty() {
        stable_hash_hex(&turns[0].content)
    } else {
        slug
    };
    let participants = if turns.iter().any(|t| t.role == "assistant") {
        vec!["user".to_string(), "assistant".to_string()]
    } else {
        vec!["owner".to_string()]
    };
    Ok(Some(ImportedConversation::from_turns(
        format!("markdown:{key}"),
        MARKDOWN_JSONL_ADAPTER_ID,
        fm_title.as_deref().or(h1),
        stem,
        "owner".to_string(),
        ts,
        ts,
        participants,
        turns,
    )))
}

fn strip_frontmatter_and_title(text: &str) -> (Option<String>, &str) {
    let Some((fm, after)) = text
        .strip_prefix("---\n")
        .and_then(|r| r.split_once("\n---\n"))
    else {
        return (None, text);
    };
    let title = fm.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("title")
            .then(|| v.trim().trim_matches(['"', '\'']).to_string())
    });
    (title, after.trim())
}

fn parse_markdown_turns(body: &str, ts: u64) -> Vec<ImportedTurn> {
    let (mut dialog, mut cur_role, mut buf) = (Vec::new(), None::<String>, Vec::new());
    let flush = |role: &mut Option<String>, buf: &mut Vec<String>, out: &mut Vec<ImportedTurn>| {
        if let Some(prev) = role.take() {
            let text = buf.join("\n").trim().to_string();
            if !text.is_empty() {
                out.push(ImportedTurn {
                    role: prev,
                    content: text,
                    timestamp: ts,
                });
            }
            buf.clear();
        }
    };
    for line in body.lines() {
        if let Some((role, rest)) = detect_speaker_header(line) {
            flush(&mut cur_role, &mut buf, &mut dialog);
            cur_role = Some(role);
            if !rest.is_empty() {
                buf.push(rest.to_string());
            }
        } else if cur_role.is_some() {
            buf.push(line.to_string());
        }
    }
    flush(&mut cur_role, &mut buf, &mut dialog);
    if dialog.len() >= 2 {
        return dialog;
    }
    let chunks: Vec<&str> = if body.contains("\n\u{00a7}\n") {
        body.split("\n\u{00a7}\n")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![body]
    };
    chunks
        .into_iter()
        .map(|c| ImportedTurn {
            role: "user".to_string(),
            content: c.to_string(),
            timestamp: ts,
        })
        .collect()
}

fn detect_speaker_header(line: &str) -> Option<(String, &str)> {
    const HEADERS: &[(&str, &str)] = &[
        ("## User", "user"),
        ("### User", "user"),
        ("**User:**", "user"),
        ("User:", "user"),
        ("Human:", "user"),
        ("## Assistant", "assistant"),
        ("### Assistant", "assistant"),
        ("**Assistant:**", "assistant"),
        ("Assistant:", "assistant"),
        ("Claude:", "assistant"),
        ("ChatGPT:", "assistant"),
    ];
    let t = line.trim();
    HEADERS.iter().find_map(|(p, r)| {
        t.strip_prefix(p)
            .map(|rest| ((*r).to_string(), rest.trim_start_matches(':').trim()))
    })
}

fn parse_generic_jsonl_file(
    path: &Path,
    rel_key: Option<&str>,
) -> Result<Option<ImportedConversation>, String> {
    let fallback_ts = file_mtime_secs(path);
    let raw = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let (mut turns, mut first_ts, mut last_ts, mut explicit_id, mut explicit_title) =
        (Vec::new(), None, fallback_ts, None, None);

    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if explicit_id.is_none() {
            explicit_id = v
                .get("conversation_id")
                .or_else(|| v.get("session_id"))
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if explicit_title.is_none() {
            explicit_title = v.get("title").and_then(Value::as_str).map(str::to_string);
        }
        let role = normalize_role(
            v.get("role")
                .or_else(|| v.get("kind"))
                .or_else(|| v.get("sender"))
                .and_then(Value::as_str)
                .unwrap_or("user"),
        );
        if role == "system" {
            continue;
        }
        let content = v
            .get("content")
            .or_else(|| v.get("text"))
            .or_else(|| v.get("message"))
            .map(extract_value_text)
            .unwrap_or_default();
        if !content.trim().is_empty() {
            let ts = parse_timestamp_secs(
                v.get("timestamp")
                    .or_else(|| v.get("at"))
                    .or_else(|| v.get("created_at")),
            )
            .unwrap_or(fallback_ts);
            first_ts.get_or_insert(ts);
            last_ts = last_ts.max(ts);
            turns.push(ImportedTurn {
                role,
                content,
                timestamp: ts,
            });
        }
    }
    if turns.is_empty() {
        return Ok(None);
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("JSONL Import");
    let slug = explicit_id
        .or_else(|| rel_key.map(sanitize_slug))
        .unwrap_or_else(|| sanitize_slug(stem));
    let key = if slug.is_empty() {
        stable_hash_hex(&turns[0].content)
    } else {
        slug
    };
    Ok(Some(ImportedConversation::from_turns(
        format!("jsonl:{key}"),
        MARKDOWN_JSONL_ADAPTER_ID,
        explicit_title.as_deref(),
        stem,
        "owner".to_string(),
        first_ts.unwrap_or(fallback_ts),
        last_ts,
        vec!["user".to_string(), "assistant".to_string()],
        turns,
    )))
}
