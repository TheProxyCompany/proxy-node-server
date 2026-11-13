//! Unit tests for `chat_import` adapters, PKZIP reader, registry inventory scanning,
//! `ImportJobTracker`, and source hygiene rules.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::DeflateEncoder;
use tempfile::tempdir;

use super::*;

fn build_single_file_zip(entry_name: &str, payload: &[u8], deflate: bool) -> Vec<u8> {
    let (method, compressed) = if deflate {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).expect("deflate write");
        (8_u16, enc.finish().expect("deflate finish"))
    } else {
        (0_u16, payload.to_vec())
    };
    let name_bytes = entry_name.as_bytes();
    let mut out = Vec::new();

    // Local file header
    out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
    out.extend_from_slice(&20_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&compressed);

    let cd_offset = out.len() as u32;
    // Central directory file header
    out.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
    out.extend_from_slice(&20_u16.to_le_bytes());
    out.extend_from_slice(&20_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(name_bytes);
    let cd_size = (out.len() as u32) - cd_offset;

    // End of central directory
    out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out
}

#[test]
fn builtin_registry_exposes_all_seven_descriptors() {
    let reg = ChatImportRegistry::builtin();
    let meta: Vec<(String, String, String)> = reg
        .descriptors()
        .into_iter()
        .map(|d| (d.adapter_id, d.brand_id, d.default_agent_id))
        .collect();
    assert_eq!(
        meta,
        vec![
            ("chatgpt".into(), "openai".into(), "gpt".into()),
            ("claude_export".into(), "anthropic".into(), "claude".into()),
            ("claude_code".into(), "claude_code".into(), "claude".into()),
            ("codex".into(), "codex".into(), "gpt".into()),
            ("hermes".into(), "hermes".into(), "proxy".into()),
            ("proxy_threads".into(), "proxy".into(), "proxy".into()),
            ("markdown_jsonl".into(), "markdown".into(), "proxy".into()),
        ]
    );
    let legacy: ChatImportAdapterDescriptor = serde_json::from_str(
        r#"{"adapter_id":"x","display_name":"X","subtitle":"s","export_hint":"h","icon_name":"i","source_kind":"export_file","extensions":[]}"#,
    )
    .expect("serde default brand/agent fields");
    assert!(legacy.brand_id.is_empty() && legacy.default_agent_id.is_empty());
}

#[test]
fn chatgpt_zip_inventory_and_selective_load() {
    let dir = tempdir().expect("tempdir");
    let json = serde_json::json!([
        {
            "id": "conv-alpha",
            "title": "Rust Mesh Architecture",
            "create_time": 1_700_000_000.0,
            "update_time": 1_700_000_120.0,
            "current_node": "n2",
            "mapping": {
                "root": { "id": "root", "parent": null, "message": null },
                "n1": {
                    "id": "n1",
                    "parent": "root",
                    "message": {
                        "author": { "role": "user" },
                        "create_time": 1_700_000_010.0,
                        "content": { "parts": ["How should oplog compaction work?"] }
                    }
                },
                "n2": {
                    "id": "n2",
                    "parent": "n1",
                    "message": {
                        "author": { "role": "assistant" },
                        "create_time": 1_700_000_050.0,
                        "content": { "parts": ["Use HLC horizons per peer."] }
                    }
                }
            }
        },
        {
            "id": "conv-beta",
            "title": "Second Chat",
            "create_time": 1_700_000_200.0,
            "update_time": 1_700_000_250.0,
            "messages": [
                { "role": "user", "content": "Ping", "timestamp": 1_700_000_210_u64 }
            ]
        }
    ]);
    let zip_bytes = build_single_file_zip("conversations.json", json.to_string().as_bytes(), true);
    let zip_path = dir.path().join("chatgpt-export.zip");
    fs::write(&zip_path, zip_bytes).expect("write zip");

    let reg = ChatImportRegistry::builtin();
    let (detected, score) = reg.detect(&zip_path).expect("detect chatgpt zip");
    assert_eq!(detected.descriptor().adapter_id, "chatgpt");
    assert!(score >= 90);

    let inv = reg
        .scan_adapter("chatgpt", Some(&zip_path), None)
        .expect("scan chatgpt");
    assert!(inv.available);
    assert_eq!(inv.conversation_count, 2);
    assert_eq!(inv.total_message_count, 3);
    assert_eq!(inv.conversations[0].source_id, "chatgpt:conv-beta");
    assert_eq!(inv.conversations[1].source_id, "chatgpt:conv-alpha");
    assert_eq!(inv.conversations[1].user_message_count, 1);
    assert_eq!(inv.conversations[1].assistant_message_count, 1);

    let selected: HashSet<String> = ["chatgpt:conv-alpha".to_string()].into_iter().collect();
    let loaded = reg
        .load_conversations("chatgpt", Some(&zip_path), None, Some(&selected))
        .expect("load selected");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].turns.len(), 2);
    assert_eq!(loaded[0].turns[0].role, "user");
    assert_eq!(loaded[0].turns[1].role, "assistant");
}

#[test]
fn claude_export_claude_code_codex_and_markdown_adapters_parse_cleanly() {
    let dir = tempdir().expect("tempdir");
    let reg = ChatImportRegistry::builtin();

    // 1. Anthropic Claude export ZIP
    let claude_json = serde_json::json!([{
        "uuid": "cl-1",
        "name": "Anthropic Design Chat",
        "created_at": "2026-11-10T14:30:00Z",
        "updated_at": "2026-11-10T14:35:00Z",
        "chat_messages": [
            { "sender": "human", "text": "Design a clean trait.", "created_at": "2026-11-10T14:30:05Z" },
            { "sender": "assistant", "content": [{ "type": "text", "text": "Keep descriptors serializable." }], "created_at": "2026-11-10T14:31:00Z" }
        ]
    }]);
    let claude_zip = dir.path().join("claude.zip");
    fs::write(
        &claude_zip,
        build_single_file_zip(
            "conversations.json",
            claude_json.to_string().as_bytes(),
            true,
        ),
    )
    .expect("write claude zip");
    let claude_convs = reg
        .load_conversations("claude_export", Some(&claude_zip), None, None)
        .expect("load claude_export");
    assert_eq!(claude_convs.len(), 1);
    assert_eq!(claude_convs[0].source_id, "claude_export:cl-1");
    assert_eq!(claude_convs[0].message_count, 2);

    // 2. Claude Code local store directory
    let cc_dir = dir.path().join(".claude").join("projects").join("repo-a");
    fs::create_dir_all(&cc_dir).expect("mkdir cc");
    let cc_jsonl = [
        serde_json::json!({ "type": "summary", "summary": "Fix sync loop", "sessionId": "sess-77" }).to_string(),
        serde_json::json!({ "type": "user", "sessionId": "sess-77", "timestamp": "2026-11-11T10:00:00Z", "message": { "content": "Inspect sync loop" } }).to_string(),
        serde_json::json!({ "type": "assistant", "sessionId": "sess-77", "timestamp": "2026-11-11T10:00:10Z", "message": { "content": [{ "type": "text", "text": "Found retry bug." }] } }).to_string(),
    ]
    .join("\n");
    fs::write(cc_dir.join("sess-77.jsonl"), cc_jsonl).expect("write cc jsonl");
    let cc_convs = reg
        .load_conversations("claude_code", Some(cc_dir.parent().unwrap()), None, None)
        .expect("load claude_code");
    assert_eq!(cc_convs.len(), 1);
    assert_eq!(cc_convs[0].source_id, "claude_code:sess-77");
    assert_eq!(cc_convs[0].title, "Fix sync loop");

    // 3. Codex CLI session JSONL (with boilerplate + duplicate item filtering)
    let codex_file = dir.path().join("rollout-1.jsonl");
    let codex_lines = [
        serde_json::json!({ "type": "session_meta", "timestamp": "2026-11-11T12:00:00Z", "payload": { "session_id": "cx-9" } }).to_string(),
        serde_json::json!({ "type": "response_item", "timestamp": "2026-11-11T12:00:01Z", "payload": { "id": "m0", "type": "message", "role": "user", "content": "<environment_context>skip</environment_context>" } }).to_string(),
        serde_json::json!({ "type": "response_item", "timestamp": "2026-11-11T12:00:02Z", "payload": { "id": "m1", "type": "message", "role": "user", "content": "Ship adapter tests" } }).to_string(),
        serde_json::json!({ "type": "response_item", "timestamp": "2026-11-11T12:00:02Z", "payload": { "id": "m1", "type": "message", "role": "user", "content": "Ship adapter tests" } }).to_string(),
        serde_json::json!({ "type": "event_msg", "timestamp": "2026-11-11T12:00:08Z", "payload": { "id": "m2", "type": "agent_message", "message": "All green." } }).to_string(),
    ]
    .join("\n");
    fs::write(&codex_file, codex_lines).expect("write codex");
    let codex_convs = reg
        .load_conversations("codex", Some(&codex_file), None, None)
        .expect("load codex");
    assert_eq!(codex_convs.len(), 1);
    assert_eq!(codex_convs[0].source_id, "codex:cx-9");
    assert_eq!(codex_convs[0].message_count, 2);

    // 4. Markdown + JSONL folder
    let notes_dir = dir.path().join("notes");
    fs::create_dir_all(&notes_dir).expect("mkdir notes");
    fs::write(
        notes_dir.join("meeting.md"),
        "---\ntitle: Architecture Notes\n---\n## User\nWhat is our target?\n## Assistant\nSub-second inventory scans.\n",
    )
    .expect("write md");
    fs::write(
        notes_dir.join("log.jsonl"),
        "{\"conversation_id\":\"j1\",\"title\":\"Quick Log\",\"role\":\"user\",\"content\":\"Hello\",\"timestamp\":1700000900}\n",
    )
    .expect("write jsonl");
    let md_convs = reg
        .load_conversations("markdown_jsonl", Some(&notes_dir), None, None)
        .expect("load markdown_jsonl");
    assert_eq!(md_convs.len(), 2);
}

#[cfg(feature = "sqlite")]
#[test]
fn hermes_and_proxy_threads_sqlite_stores_scan_and_overview() {
    let dir = tempdir().expect("tempdir");
    let reg = ChatImportRegistry::builtin();

    // Build Hermes profile store (~/.hermes/profiles/default/state.db + memory_store.db)
    let hermes_root = dir.path().join("hermes-home");
    let prof_dir = hermes_root.join("profiles").join("default");
    fs::create_dir_all(&prof_dir).expect("mkdir hermes profile");
    {
        let conn = rusqlite::Connection::open(prof_dir.join("state.db")).expect("open state.db");
        conn.execute_batch(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT, started_at TEXT, ended_at TEXT);
             CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, timestamp TEXT);
             INSERT INTO sessions VALUES ('h-1', 'Triage Run', '2026-11-12T08:00:00Z', '2026-11-12T08:05:00Z');
             INSERT INTO messages VALUES (1, 'h-1', 'user', 'Check open PRs', '2026-11-12T08:00:10Z');
             INSERT INTO messages VALUES (2, 'h-1', 'assistant', '3 PRs ready.', '2026-11-12T08:01:00Z');",
        )
        .expect("seed hermes state.db");
    }
    {
        let conn = rusqlite::Connection::open(prof_dir.join("memory_store.db"))
            .expect("open memory_store.db");
        conn.execute_batch(
            "CREATE TABLE facts (id INTEGER PRIMARY KEY, category TEXT, content TEXT, created_at TEXT);
             INSERT INTO facts VALUES (1, 'prefs', 'Prefers concise Rust modules', '2026-11-12T09:00:00Z');",
        )
        .expect("seed hermes facts");
    }
    let hermes_inv = reg
        .scan_adapter("hermes", Some(&hermes_root), None)
        .expect("scan hermes");
    assert_eq!(hermes_inv.conversation_count, 2);
    assert_eq!(hermes_inv.total_message_count, 3);

    // Build Local Proxy proxy.db with direct + party scopes
    let proxy_root = dir.path().join("proxy-data");
    fs::create_dir_all(&proxy_root).expect("mkdir proxy_root");
    {
        let conn = rusqlite::Connection::open(proxy_root.join("proxy.db")).expect("open proxy.db");
        conn.execute_batch(
            "CREATE TABLE conversations (id TEXT PRIMARY KEY, title TEXT, kind TEXT, archived INTEGER, created_at TEXT, updated_at TEXT);
             CREATE TABLE conversation_participants (id TEXT PRIMARY KEY, conversation_id TEXT, participant_name TEXT, agent_id TEXT, role TEXT);
             CREATE TABLE items (id TEXT PRIMARY KEY, conversation_id TEXT, type TEXT, role TEXT, content TEXT, created_at TEXT);
             INSERT INTO conversations VALUES ('proxy.direct.main', 'Direct Thread', 'direct', 0, '2026-11-12T10:00:00Z', '2026-11-12T10:05:00Z');
             INSERT INTO conversations VALUES ('party.ops-room', 'Ops Room', 'party', 0, '2026-11-12T11:00:00Z', '2026-11-12T11:05:00Z');
             INSERT INTO items VALUES ('i1', 'proxy.direct.main', 'message', 'user', 'Status report?', '2026-11-12T10:01:00Z');
             INSERT INTO items VALUES ('i2', 'party.ops-room', 'message', 'assistant', 'Deploying mesh.', '2026-11-12T11:01:00Z');",
        )
        .expect("seed proxy.db");
    }

    util::with_test_home_dir(dir.path(), || {
        let overview = reg.overview(Some(&proxy_root));
        let pt_overview = overview
            .iter()
            .find(|o| o.descriptor.adapter_id == "proxy_threads")
            .expect("proxy_threads overview");
        assert!(pt_overview.available);
        assert_eq!(pt_overview.conversation_count, 2);
        assert_eq!(pt_overview.total_message_count, 2);
    });

    let pt_convs = reg
        .load_conversations("proxy_threads", None, Some(&proxy_root), None)
        .expect("load proxy_threads");
    assert_eq!(pt_convs.len(), 2);
    assert_eq!(pt_convs[0].scope, "party:ops-room");
    assert_eq!(pt_convs[1].scope, "owner");
}

#[test]
fn import_job_tracker_tracks_progress_and_cancellation() {
    let tracker = ImportJobTracker::new();
    let snap = tracker.start_job(
        "job-1",
        "agent-mogul",
        "chatgpt",
        "ChatGPT",
        Some("/tmp/export.zip".to_string()),
        vec![("chatgpt:c1".to_string(), 4), ("chatgpt:c2".to_string(), 2)],
    );
    assert_eq!(snap.status, "running");
    assert_eq!(snap.total_conversations, 2);
    assert_eq!(snap.total_messages, 6);
    assert_eq!(snap.conversation_states["chatgpt:c1"].status, "queued");

    tracker.begin_conversation("job-1", "chatgpt:c1", "First Chat", 4);
    tracker.advance_messages("job-1", "chatgpt:c1", 2, 1);
    let mid = tracker.get_job("job-1").expect("mid snapshot");
    assert_eq!(mid.processed_messages, 2);
    assert_eq!(mid.extracted_facts, 1);
    assert_eq!(
        mid.current_conversation_title.as_deref(),
        Some("First Chat")
    );

    tracker.finish_conversation("job-1", "chatgpt:c1", "done", 2);
    tracker.finish_conversation("job-1", "chatgpt:c2", "skipped", 0);
    assert!(!tracker.is_cancelled("job-1"));
    assert!(tracker.request_cancel("job-1"));
    assert!(tracker.is_cancelled("job-1"));

    let final_snap = tracker
        .finish_job("job-1", "cancelled", None)
        .expect("finish job");
    assert_eq!(final_snap.status, "cancelled");
    assert_eq!(final_snap.completed_conversations, 1);
    assert_eq!(final_snap.skipped_conversations, 1);
    assert_eq!(final_snap.processed_messages, 4);
    assert_eq!(final_snap.extracted_facts, 3);
    assert!(final_snap.current_conversation_id.is_none());
    assert!(!tracker.request_cancel("job-1"));

    let listed = tracker.list_jobs_for_agent("agent-mogul");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].job_id, "job-1");
}

#[cfg(feature = "sqlite")]
#[test]
fn mesh_synced_proxy_db_populates_adapters_and_scopes_proxy_threads() {
    let dir = tempdir().expect("tempdir");
    let fake_home = dir.path().join("fake-home");
    fs::create_dir_all(&fake_home).expect("mkdir fake_home");
    // Seed local ~/.claude/projects (with overlapping sess-shared) and ~/.codex/sessions,
    // while leaving ~/.hermes completely absent on disk!
    let cc_dir = fake_home.join(".claude").join("projects").join("p1");
    let cx_dir = fake_home.join(".codex").join("sessions");
    fs::create_dir_all(&cc_dir).expect("mkdir cc");
    fs::create_dir_all(&cx_dir).expect("mkdir cx");
    fs::write(
        cc_dir.join("sess-shared.jsonl"),
        serde_json::json!({ "type": "user", "sessionId": "sess-shared", "timestamp": "2026-11-12T10:00:00Z", "message": { "content": "Local claude turn" } }).to_string(),
    )
    .expect("write local cc");
    fs::write(
        cx_dir.join("cx-local.jsonl"),
        serde_json::json!({ "type": "event_msg", "timestamp": "2026-11-12T10:00:00Z", "payload": { "id": "m1", "type": "user_message", "message": "Local codex turn" } }).to_string(),
    )
    .expect("write local cx");

    let proxy_root = dir.path().join("mesh-data");
    fs::create_dir_all(&proxy_root).expect("mkdir proxy_root");
    let conn = rusqlite::Connection::open(proxy_root.join("proxy.db")).expect("open proxy.db");
    conn.execute_batch(
        "CREATE TABLE conversations (id TEXT PRIMARY KEY, source_provider TEXT, source_id TEXT, title TEXT, kind TEXT, archived INTEGER, created_at TEXT, updated_at TEXT);
         CREATE TABLE items (id TEXT PRIMARY KEY, conversation_id TEXT, type TEXT, role TEXT, content TEXT, created_at TEXT);
         INSERT INTO conversations VALUES ('ext-h1', 'hermes', 'h-mesh-1', 'Mesh Hermes Run', 'direct', 0, '2026-11-12T12:00:00Z', '2026-11-12T12:05:00Z');
         INSERT INTO conversations VALUES ('ext-cc1', 'claude_code', 'sess-shared', 'Dup Claude', 'direct', 0, '2026-11-12T12:00:00Z', '2026-11-12T12:05:00Z');
         INSERT INTO conversations VALUES ('ext-cc2', 'claude-code', 'sess-mesh-2', 'Mesh Claude 2', 'direct', 0, '2026-11-12T12:10:00Z', '2026-11-12T12:15:00Z');
         INSERT INTO conversations VALUES ('ext-cx1', 'codex', 'cx-mesh-1', 'Mesh Codex Run', 'direct', 0, '2026-11-12T12:20:00Z', '2026-11-12T12:25:00Z');
         INSERT INTO conversations VALUES ('proxy.direct.1', 'proxy', NULL, 'Native Direct', 'direct', 0, '2026-11-12T12:30:00Z', '2026-11-12T12:35:00Z');
         INSERT INTO conversations VALUES ('party.ops', NULL, NULL, 'Native Null Provider', 'party', 0, '2026-11-12T12:40:00Z', '2026-11-12T12:45:00Z');
         INSERT INTO items VALUES ('m1', 'ext-h1', 'message', 'user', 'Sync hermes', '2026-11-12T12:01:00Z');
         INSERT INTO items VALUES ('m2', 'ext-h1', 'message', 'assistant', 'Synced.', '2026-11-12T12:02:00Z');
         INSERT INTO items VALUES ('m3', 'ext-cc1', 'message', 'user', 'Dup turn', '2026-11-12T12:01:00Z');
         INSERT INTO items VALUES ('m4', 'ext-cc2', 'message', 'assistant', 'Remote claude', '2026-11-12T12:11:00Z');
         INSERT INTO items VALUES ('m5', 'ext-cx1', 'message', 'user', 'Remote codex', '2026-11-12T12:21:00Z');
         INSERT INTO items VALUES ('m6', 'proxy.direct.1', 'message', 'user', 'Hello Proxy', '2026-11-12T12:31:00Z');
         INSERT INTO items VALUES ('m7', 'party.ops', 'message', 'assistant', 'Party ready', '2026-11-12T12:41:00Z');",
    )
    .expect("seed mixed proxy.db");
    drop(conn);

    util::with_test_home_dir(&fake_home, || {
        assert!(!fake_home.join(".hermes").exists());
        let reg = ChatImportRegistry::builtin();
        let ov = reg.overview(Some(&proxy_root));
        let stat = |id: &str| {
            let o = ov.iter().find(|o| o.descriptor.adapter_id == id).unwrap();
            (o.available, o.conversation_count, o.total_message_count)
        };
        assert_eq!(stat("hermes"), (true, 1, 2));
        assert_eq!(stat("claude_code"), (true, 2, 2));
        assert_eq!(stat("codex"), (true, 2, 2));
        assert_eq!(stat("proxy_threads"), (true, 2, 2));
        let h_convs = reg
            .load_conversations("hermes", None, Some(&proxy_root), None)
            .expect("load mesh hermes without ~/.hermes");
        assert_eq!(h_convs.len(), 1);
        assert_eq!(h_convs[0].source_id, "hermes:session:h-mesh-1");
        let pt_convs = reg
            .load_conversations("proxy_threads", None, Some(&proxy_root), None)
            .expect("load scoped proxy_threads");
        assert_eq!(pt_convs.len(), 2);
        assert!(pt_convs.iter().all(|c| c.adapter_id == "proxy_threads"));
    });
}

#[test]
fn chat_import_files_stay_under_500_lines_and_em_dash_free() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("chat_import");
    let mut files = Vec::new();
    walk(&dir, &mut files);
    assert!(!files.is_empty());
    for file in files {
        let text = fs::read_to_string(&file).expect("read rs");
        let lines = text.lines().count();
        assert!(
            lines < 500,
            "{} has {} lines (must be strictly < 500)",
            file.display(),
            lines
        );
        assert!(
            !text.contains('\u{2014}'),
            "{} contains forbidden U+2014 em dash",
            file.display()
        );
    }
}
