//! Hermes Agent local SQLite session (`state.db`: `sessions` + `messages`) and fact store
//! (`memory_store.db`: `facts`) adapter (`~/.hermes`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(feature = "sqlite")]
use rusqlite::{Connection, OpenFlags, params};

use super::{
    HERMES_MESH_SPEC, HERMES_PROVIDERS, mesh_load_conversations, mesh_resolve_source,
    mesh_scan_manifests,
};
#[cfg(feature = "sqlite")]
use super::{has_sqlite_table, sqlite_opt_col, sqlite_table_columns};
use crate::chat_import::{
    ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind, ConversationManifest,
    HERMES_ADAPTER_ID, ImportedConversation, user_home_dir,
};
#[cfg(feature = "sqlite")]
use crate::chat_import::{
    ImportedTurn, file_mtime_secs, normalize_role, parse_timestamp_str, stable_hash_hex,
    truncate_chars,
};

pub struct HermesAdapter;

impl ChatImportAdapter for HermesAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: HERMES_ADAPTER_ID.to_string(),
            display_name: "Hermes Agent".to_string(),
            subtitle: "Local or mesh-synced Hermes Agent sessions and facts".to_string(),
            export_hint: "Automatically discovered from ~/.hermes and mesh-synced proxy.db threads"
                .to_string(),
            icon_name: "bolt.horizontal.circle".to_string(),
            source_kind: ChatImportSourceKind::LocalStore.into(),
            extensions: vec!["db".into(), "sqlite".into(), "sqlite3".into()],
            brand_id: "hermes".to_string(),
            default_agent_id: "proxy".to_string(),
        }
    }

    fn default_local_path(&self, _data_root: Option<&Path>) -> Option<PathBuf> {
        user_home_dir().map(|home| home.join(".hermes"))
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
            HERMES_PROVIDERS,
        )
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        if path.is_dir() {
            return u8::from(!collect_hermes_dbs(path).is_empty()) * 94;
        }
        if !head.starts_with(b"SQLite format 3\0") {
            return 0;
        }
        sniff_sqlite_file(path)
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        parse_hermes_path(path, None)
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
            HERMES_PROVIDERS,
            &HERMES_MESH_SPEC,
            scan_hermes_path,
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
            HERMES_PROVIDERS,
            &HERMES_MESH_SPEC,
            selected_ids,
            parse_hermes_path,
        )
    }
}

fn collect_hermes_dbs(dir: &Path) -> Vec<PathBuf> {
    let mut dbs = Vec::new();
    push_dir_dbs(dir, &mut dbs);
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut children: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        children.sort();
        for child in children.into_iter().filter(|p| p.is_dir()) {
            push_dir_dbs(&child, &mut dbs);
            if child.file_name().and_then(|s| s.to_str()) == Some("profiles")
                && let Ok(profiles) = std::fs::read_dir(&child)
            {
                let mut profs: Vec<PathBuf> =
                    profiles.filter_map(|e| e.ok().map(|e| e.path())).collect();
                profs.sort();
                for prof in profs.into_iter().filter(|p| p.is_dir()) {
                    push_dir_dbs(&prof, &mut dbs);
                }
            }
        }
    }
    dbs
}

fn push_dir_dbs(dir: &Path, out: &mut Vec<PathBuf>) {
    for name in ["state.db", "memory_store.db"] {
        let p = dir.join(name);
        if p.is_file() {
            out.push(p);
        }
    }
}

#[cfg(not(feature = "sqlite"))]
fn sniff_sqlite_file(path: &Path) -> u8 {
    let f = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    u8::from(f.eq_ignore_ascii_case("state.db") || f.eq_ignore_ascii_case("memory_store.db")) * 90
}

#[cfg(not(feature = "sqlite"))]
fn scan_hermes_path(_path: &Path) -> Result<Vec<ConversationManifest>, String> {
    Err("sqlite feature is not enabled in proxy-node-server".to_string())
}

#[cfg(not(feature = "sqlite"))]
fn parse_hermes_path(
    _path: &Path,
    _selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    Err("sqlite feature is not enabled in proxy-node-server".to_string())
}

#[cfg(feature = "sqlite")]
fn open_ro(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("opening SQLite DB {}: {e}", path.display()))
}

#[cfg(feature = "sqlite")]
fn sniff_sqlite_file(path: &Path) -> u8 {
    let Ok(conn) = open_ro(path) else { return 0 };
    if has_sqlite_table(&conn, "sessions") && has_sqlite_table(&conn, "messages") {
        return 97;
    }
    if has_sqlite_table(&conn, "facts") && !has_sqlite_table(&conn, "conversations") {
        let is_mem = path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|f| f.eq_ignore_ascii_case("memory_store.db"));
        return if is_mem { 96 } else { 88 };
    }
    0
}

#[cfg(feature = "sqlite")]
fn scan_hermes_path(path: &Path) -> Result<Vec<ConversationManifest>, String> {
    let dbs = if path.is_dir() {
        collect_hermes_dbs(path)
    } else {
        vec![path.to_path_buf()]
    };
    let (mut seen, mut out) = (HashSet::new(), Vec::new());
    for db in dbs {
        let fallback_ts = file_mtime_secs(&db);
        let conn = open_ro(&db)?;
        if has_sqlite_table(&conn, "sessions") && has_sqlite_table(&conn, "messages") {
            for m in scan_sessions_manifests(&conn, fallback_ts)? {
                if seen.insert(m.source_id.clone()) {
                    out.push(m);
                }
            }
        }
        if has_sqlite_table(&conn, "facts") {
            for c in parse_facts_table(&conn, &db, fallback_ts)? {
                if seen.insert(c.source_id.clone()) {
                    out.push(c.summary());
                }
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "sqlite")]
fn scan_sessions_manifests(
    conn: &Connection,
    fallback_ts: u64,
) -> Result<Vec<ConversationManifest>, String> {
    let cols = sqlite_table_columns(conn, "sessions");
    let sum: i64 = if cols.iter().any(|c| c == "message_count") {
        conn.query_row(
            "SELECT COALESCE(SUM(COALESCE(message_count, 0)), 0) FROM sessions",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    } else {
        0
    };
    if sum == 0 {
        return Ok(parse_sessions_table(conn, fallback_ts, None)?
            .iter()
            .map(ImportedConversation::summary)
            .collect());
    }
    let sql = format!(
        "SELECT CAST(id AS TEXT), {}, {}, {}, {}, COALESCE(message_count, 0)
         FROM sessions WHERE COALESCE(message_count, 0) > 0 ORDER BY rowid ASC",
        sqlite_opt_col(&cols, &["title"], ""),
        sqlite_opt_col(&cols, &["display_name"], ""),
        sqlite_opt_col(&cols, &["started_at", "created_at"], ""),
        sqlite_opt_col(&cols, &["last_activity_at", "ended_at", "updated_at"], ""),
    );
    let (mut stmt, mut out) = (
        conn.prepare(&sql)
            .map_err(|e| format!("sessions sql: {e}"))?,
        Vec::new(),
    );
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })
        .map_err(|e| format!("sessions rows: {e}"))?;
    for (sid, raw_title, disp, s_raw, u_raw, count_raw) in rows.flatten() {
        let msg_count = usize::try_from(count_raw.max(0)).unwrap_or(0);
        if msg_count == 0 {
            continue;
        }
        let created_at = s_raw
            .as_deref()
            .and_then(parse_timestamp_str)
            .unwrap_or(fallback_ts);
        let updated_at = u_raw
            .as_deref()
            .and_then(parse_timestamp_str)
            .unwrap_or(created_at)
            .max(created_at);
        let title = disp
            .as_deref()
            .or(raw_title.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|t| truncate_chars(t, 120))
            .unwrap_or_else(|| format!("Hermes Session ({sid})"));
        out.push(ConversationManifest {
            source_id: format!("hermes:session:{sid}"),
            adapter_id: HERMES_ADAPTER_ID.to_string(),
            preview: title.clone(),
            title,
            scope: "owner".to_string(),
            message_count: msg_count,
            user_message_count: msg_count / 2,
            assistant_message_count: msg_count.saturating_sub(msg_count / 2),
            created_at,
            updated_at,
            participants: vec!["user".to_string(), "Hermes".to_string()],
        });
    }
    Ok(out)
}

#[cfg(feature = "sqlite")]
fn parse_hermes_path(
    path: &Path,
    selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    let dbs = if path.is_dir() {
        collect_hermes_dbs(path)
    } else {
        vec![path.to_path_buf()]
    };
    let (mut seen, mut out) = (HashSet::new(), Vec::new());
    let want_facts =
        selected.is_none_or(|ids| ids.iter().any(|id| id.starts_with("hermes:facts:")));
    for db in dbs {
        let fallback_ts = file_mtime_secs(&db);
        let conn = open_ro(&db)?;
        if has_sqlite_table(&conn, "sessions") && has_sqlite_table(&conn, "messages") {
            for conv in parse_sessions_table(&conn, fallback_ts, selected)? {
                if seen.insert(conv.source_id.clone()) {
                    out.push(conv);
                }
            }
        }
        if want_facts && has_sqlite_table(&conn, "facts") {
            for conv in parse_facts_table(&conn, &db, fallback_ts)? {
                if seen.insert(conv.source_id.clone()) {
                    out.push(conv);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "sqlite")]
type SessionRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[cfg(feature = "sqlite")]
fn parse_sessions_table(
    conn: &Connection,
    fallback_ts: u64,
    selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    let cols = sqlite_table_columns(conn, "sessions");
    let sql = format!(
        "SELECT CAST(id AS TEXT), {}, {}, {}, {} FROM sessions ORDER BY rowid ASC",
        sqlite_opt_col(&cols, &["title"], ""),
        sqlite_opt_col(&cols, &["display_name"], ""),
        sqlite_opt_col(&cols, &["started_at", "created_at"], ""),
        sqlite_opt_col(&cols, &["ended_at", "updated_at"], ""),
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| format!("sessions: {e}"))?;
    let sessions: Vec<SessionRow> = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .map_err(|e| format!("sessions rows: {e}"))?
        .filter_map(Result::ok)
        .collect();

    let msg_cols = sqlite_table_columns(conn, "messages");
    let msg_sql = format!(
        "SELECT CAST(COALESCE(role, 'user') AS TEXT), CAST(COALESCE(content, '') AS TEXT), {}
         FROM messages WHERE session_id = ?1 ORDER BY rowid ASC",
        sqlite_opt_col(&msg_cols, &["timestamp", "created_at"], ""),
    );
    let mut msg_stmt = conn
        .prepare(&msg_sql)
        .map_err(|e| format!("messages: {e}"))?;
    let mut out = Vec::new();
    for (sid, raw_title, disp, s_raw, e_raw) in sessions {
        let source_id = format!("hermes:session:{sid}");
        if selected.is_some_and(|ids| !ids.contains(&source_id)) {
            continue;
        }
        let created_at = s_raw
            .as_deref()
            .and_then(parse_timestamp_str)
            .unwrap_or(fallback_ts);
        let updated_at = e_raw
            .as_deref()
            .and_then(parse_timestamp_str)
            .unwrap_or(created_at);
        let turns: Vec<ImportedTurn> = msg_stmt
            .query_map(params![&sid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|e| format!("messages {sid}: {e}"))?
            .flatten()
            .filter_map(|(role_raw, content, ts_str)| {
                let role = normalize_role(&role_raw);
                (role != "system" && !content.trim().is_empty()).then(|| ImportedTurn {
                    role,
                    content: content.trim().to_string(),
                    timestamp: ts_str
                        .as_deref()
                        .and_then(parse_timestamp_str)
                        .unwrap_or(created_at),
                })
            })
            .collect();
        if turns.is_empty() {
            continue;
        }
        let chosen = disp
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or(raw_title.as_deref());
        out.push(ImportedConversation::from_turns(
            source_id,
            HERMES_ADAPTER_ID,
            chosen,
            "Hermes Session",
            "owner".to_string(),
            created_at,
            updated_at,
            vec!["user".to_string(), "Hermes".to_string()],
            turns,
        ));
    }
    Ok(out)
}

#[cfg(feature = "sqlite")]
fn parse_facts_table(
    conn: &Connection,
    path: &Path,
    fallback_ts: u64,
) -> Result<Vec<ImportedConversation>, String> {
    let cols = sqlite_table_columns(conn, "facts");
    let cat = if cols.iter().any(|c| c == "category") {
        "CAST(COALESCE(category, 'general') AS TEXT)"
    } else {
        "'general'"
    };
    let sql = format!(
        "SELECT CAST(content AS TEXT), {cat}, {} FROM facts ORDER BY rowid ASC",
        sqlite_opt_col(&cols, &["created_at"], ""),
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| format!("facts: {e}"))?;
    let (mut turns, mut min_ts, mut max_ts) = (Vec::new(), None, fallback_ts);
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|e| format!("facts rows: {e}"))?;
    for (content, cat, ts_raw) in rows.flatten() {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            let ts = ts_raw
                .as_deref()
                .and_then(parse_timestamp_str)
                .unwrap_or(fallback_ts);
            min_ts.get_or_insert(ts);
            max_ts = max_ts.max(ts);
            turns.push(ImportedTurn {
                role: "assistant".to_string(),
                content: format!("[{cat}] {trimmed}"),
                timestamp: ts,
            });
        }
    }
    if turns.is_empty() {
        return Ok(Vec::new());
    }
    let db_key = stable_hash_hex(&turns[0].content);
    let label = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("memory_store.db");
    let title = format!("Imported Facts ({label})");
    Ok(vec![ImportedConversation::from_turns(
        format!("hermes:facts:{db_key}"),
        HERMES_ADAPTER_ID,
        Some(&title),
        "Imported Facts",
        "owner".to_string(),
        min_ts.unwrap_or(fallback_ts),
        max_ts,
        vec!["Fact Store".to_string()],
        turns,
    )])
}
