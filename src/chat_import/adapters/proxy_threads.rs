//! Local Proxy SQLite `proxy.db` (`conversations`, `items` / `messages`,
//! `conversation_participants`) adapter (`<data_root>/proxy.db`).

use std::path::{Path, PathBuf};

#[cfg(feature = "sqlite")]
use rusqlite::{Connection, OpenFlags, params};

#[cfg(feature = "sqlite")]
use super::{has_sqlite_table, sqlite_opt_col, sqlite_table_columns};
use crate::chat_import::{
    ChatImportAdapter, ChatImportAdapterDescriptor, ChatImportSourceKind, ImportedConversation,
    PROXY_THREADS_ADAPTER_ID,
};
#[cfg(feature = "sqlite")]
use crate::chat_import::{ImportedTurn, file_mtime_secs, normalize_role, parse_timestamp_str};

pub struct ProxyThreadsAdapter;

impl ChatImportAdapter for ProxyThreadsAdapter {
    fn descriptor(&self) -> ChatImportAdapterDescriptor {
        ChatImportAdapterDescriptor {
            adapter_id: PROXY_THREADS_ADAPTER_ID.to_string(),
            display_name: "Local Proxy Threads".to_string(),
            subtitle: "Existing conversations on this Proxy node (proxy.db)".to_string(),
            export_hint: "Automatically discovered from local Proxy data directory".to_string(),
            icon_name: "person.2.wave.2".to_string(),
            source_kind: ChatImportSourceKind::LocalStore.into(),
            extensions: vec![
                "db".to_string(),
                "sqlite".to_string(),
                "sqlite3".to_string(),
            ],
        }
    }

    fn default_local_path(&self, data_root: Option<&Path>) -> Option<PathBuf> {
        let root = data_root?;
        let is_db = root.extension().and_then(|s| s.to_str()).is_some_and(|e| {
            matches!(e.to_ascii_lowercase().as_str(), "db" | "sqlite" | "sqlite3")
        });
        if is_db {
            Some(root.to_path_buf())
        } else {
            Some(root.join("proxy.db"))
        }
    }

    fn sniff(&self, path: &Path, head: &[u8]) -> u8 {
        if path.is_dir() {
            return u8::from(path.join("proxy.db").is_file()) * 95;
        }
        if !head.starts_with(b"SQLite format 3\0") {
            return 0;
        }
        sniff_proxy_db(path)
    }

    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String> {
        parse_proxy_db(path, None)
    }

    fn parse_selected_conversations(
        &self,
        path: &Path,
        selected_ids: Option<&std::collections::HashSet<String>>,
    ) -> Result<Vec<ImportedConversation>, String> {
        parse_proxy_db(path, selected_ids)
    }
}

#[cfg(not(feature = "sqlite"))]
fn sniff_proxy_db(path: &Path) -> u8 {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if fname.eq_ignore_ascii_case("proxy.db") {
        95
    } else {
        0
    }
}

#[cfg(not(feature = "sqlite"))]
fn parse_proxy_db(
    _path: &Path,
    _selected: Option<&std::collections::HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    Err("sqlite feature is not enabled in proxy-node-server".to_string())
}

#[cfg(feature = "sqlite")]
type ConvRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[cfg(feature = "sqlite")]
fn sniff_proxy_db(path: &Path) -> u8 {
    let Ok(conn) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return 0;
    };
    u8::from(
        has_sqlite_table(&conn, "conversations")
            && (has_sqlite_table(&conn, "items") || has_sqlite_table(&conn, "messages")),
    ) * 98
}

#[cfg(feature = "sqlite")]
fn parse_proxy_db(
    path: &Path,
    selected: Option<&std::collections::HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    let db_path = if path.is_dir() {
        path.join("proxy.db")
    } else {
        path.to_path_buf()
    };
    let fallback_ts = file_mtime_secs(&db_path);
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("opening proxy.db {}: {e}", db_path.display()))?;

    let cols = sqlite_table_columns(&conn, "conversations");
    let archived = if cols.iter().any(|c| c == "archived") {
        "WHERE COALESCE(c.archived, 0) = 0"
    } else {
        ""
    };
    let kind_expr = if cols.iter().any(|c| c == "kind") {
        "CAST(c.kind AS TEXT)"
    } else {
        "'direct'"
    };
    let sql = format!(
        "SELECT CAST(c.id AS TEXT), {}, {kind_expr}, {}, {} FROM conversations c {archived} ORDER BY c.rowid ASC",
        sqlite_opt_col(&cols, &["title"], "c."),
        sqlite_opt_col(&cols, &["created_at"], "c."),
        sqlite_opt_col(&cols, &["updated_at"], "c."),
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("preparing conversations query: {e}"))?;
    let convs: Vec<ConvRow> = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .map_err(|e| format!("querying conversations: {e}"))?
        .filter_map(Result::ok)
        .collect();

    let (has_parts, has_items, has_msgs) = (
        has_sqlite_table(&conn, "conversation_participants"),
        has_sqlite_table(&conn, "items"),
        has_sqlite_table(&conn, "messages"),
    );
    let mut out = Vec::new();
    for (cid, raw_title, kind_opt, created_raw, updated_raw) in convs {
        let source_id = format!("proxy_threads:{cid}");
        if selected.is_some_and(|ids| !ids.contains(&source_id)) {
            continue;
        }
        let kind = kind_opt.unwrap_or_else(|| "direct".to_string());
        let created_at = created_raw
            .as_deref()
            .and_then(parse_timestamp_str)
            .unwrap_or(fallback_ts);
        let updated_at = updated_raw
            .as_deref()
            .and_then(parse_timestamp_str)
            .unwrap_or(created_at);
        let participants = if has_parts {
            read_participants(&conn, &cid)
        } else {
            Vec::new()
        };
        let scope = resolve_scope(&cid, &kind, &participants);

        let mut turns = if has_items {
            read_table_turns(&conn, "items", &cid, created_at)?
        } else {
            Vec::new()
        };
        if turns.is_empty() && has_msgs {
            turns = read_table_turns(&conn, "messages", &cid, created_at)?;
        }
        if turns.is_empty() {
            continue;
        }
        out.push(ImportedConversation::from_turns(
            source_id,
            PROXY_THREADS_ADAPTER_ID,
            raw_title.as_deref(),
            &cid,
            scope,
            created_at,
            updated_at,
            if participants.is_empty() {
                vec!["owner".to_string(), "Proxy".to_string()]
            } else {
                participants
            },
            turns,
        ));
    }
    Ok(out)
}

#[cfg(feature = "sqlite")]
fn resolve_scope(cid: &str, kind: &str, participants: &[String]) -> String {
    let k = kind.trim().to_ascii_lowercase();
    if k == "party" {
        return format!("party:{}", cid.strip_prefix("party.").unwrap_or(cid));
    }
    if k == "direct" || cid.starts_with("proxy.direct.") {
        return "owner".to_string();
    }
    if participants.len() > 2 {
        return format!("party:{cid}");
    }
    "owner".to_string()
}

#[cfg(feature = "sqlite")]
fn read_participants(conn: &Connection, cid: &str) -> Vec<String> {
    let cols = sqlite_table_columns(conn, "conversation_participants");
    let expr =
        if cols.iter().any(|c| c == "participant_name") && cols.iter().any(|c| c == "agent_id") {
            "COALESCE(participant_name, agent_id, role, id)"
        } else if cols.iter().any(|c| c == "participant_name") {
            "COALESCE(participant_name, id)"
        } else if cols.iter().any(|c| c == "name") {
            "COALESCE(name, id)"
        } else {
            "id"
        };
    let sql = format!(
        "SELECT CAST({expr} AS TEXT) FROM conversation_participants WHERE conversation_id = ?1 ORDER BY rowid ASC"
    );
    let Ok(mut st) = conn.prepare(&sql) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(rows) = st.query_map(params![cid], |r| r.get::<_, String>(0)) {
        for name in rows.flatten() {
            let t = name.trim();
            if !t.is_empty() && !out.iter().any(|p| p == t) {
                out.push(t.to_string());
            }
        }
    }
    out
}

#[cfg(feature = "sqlite")]
fn read_table_turns(
    conn: &Connection,
    table: &str,
    cid: &str,
    default_ts: u64,
) -> Result<Vec<ImportedTurn>, String> {
    let cols = sqlite_table_columns(conn, table);
    let fk = if cols.iter().any(|c| c == "conversation_id") {
        "conversation_id"
    } else {
        "session_id"
    };
    let type_filter = if table == "items" && cols.iter().any(|c| c == "type") {
        "AND COALESCE(type, 'message') = 'message'"
    } else {
        ""
    };
    let sql = format!(
        "SELECT CAST(COALESCE(role, 'user') AS TEXT), CAST(COALESCE(content, '') AS TEXT), {}
         FROM \"{table}\" WHERE \"{fk}\" = ?1 {type_filter} ORDER BY rowid ASC",
        sqlite_opt_col(&cols, &["created_at", "timestamp"], ""),
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("preparing {table} turns query: {e}"))?;
    let rows = stmt
        .query_map(params![cid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|e| format!("querying {table} turns: {e}"))?;
    let mut turns = Vec::new();
    for (role_raw, content, ts_raw) in rows.flatten() {
        let role = normalize_role(&role_raw);
        if role != "system" && !content.trim().is_empty() {
            turns.push(ImportedTurn {
                role,
                content: content.trim().to_string(),
                timestamp: ts_raw
                    .as_deref()
                    .and_then(parse_timestamp_str)
                    .unwrap_or(default_ts),
            });
        }
    }
    Ok(turns)
}
