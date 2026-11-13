//! Local Proxy SQLite `proxy.db` (`conversations`, `items` / `messages`,
//! `conversation_participants`) adapter (`<data_root>/proxy.db`) and shared
//! `source_provider` query helpers for mesh-synced external harness threads.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(feature = "sqlite")]
use rusqlite::{Connection, OpenFlags, Statement, params};

#[cfg(feature = "sqlite")]
use super::ProviderFilter;
use super::{PROXY_NATIVE_SPEC, ProxyDbAdapterSpec};
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
            brand_id: "proxy".to_string(),
            default_agent_id: "proxy".to_string(),
        }
    }

    fn default_local_path(&self, data_root: Option<&Path>) -> Option<PathBuf> {
        resolve_proxy_db_path(data_root)
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
        parse_proxy_db_for_spec(path, &PROXY_NATIVE_SPEC, None)
    }

    fn load_conversations(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
        selected_ids: Option<&HashSet<String>>,
    ) -> Result<Vec<ImportedConversation>, String> {
        let target = custom_path
            .map(Path::to_path_buf)
            .or_else(|| self.default_local_path(data_root))
            .ok_or_else(|| {
                format!(
                    "adapter '{}' requires an explicit file path",
                    PROXY_THREADS_ADAPTER_ID
                )
            })?;
        if !target.exists() {
            return Err(format!("import path does not exist: {}", target.display()));
        }
        parse_proxy_db_for_spec(&target, &PROXY_NATIVE_SPEC, selected_ids)
    }
}

pub(crate) fn resolve_proxy_db_path(data_root: Option<&Path>) -> Option<PathBuf> {
    let root = data_root?;
    let is_db = root
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "db" | "sqlite" | "sqlite3"));
    if is_db {
        Some(root.to_path_buf())
    } else {
        Some(root.join("proxy.db"))
    }
}

pub(crate) fn is_proxy_db_file(path: &Path) -> bool {
    let candidate = if path.is_dir() {
        path.join("proxy.db")
    } else {
        path.to_path_buf()
    };
    candidate.is_file() && sniff_proxy_db(&candidate) > 0
}

#[cfg(not(feature = "sqlite"))]
pub(crate) fn proxy_db_has_provider(_data_root: Option<&Path>, _providers: &[&str]) -> bool {
    false
}

#[cfg(not(feature = "sqlite"))]
pub(crate) fn parse_optional_mesh_proxy_db(
    _data_root: Option<&Path>,
    _spec: &ProxyDbAdapterSpec,
    _selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    Ok(Vec::new())
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
pub(crate) fn parse_proxy_db_for_spec(
    _path: &Path,
    _spec: &ProxyDbAdapterSpec,
    _selected: Option<&HashSet<String>>,
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
    Option<String>,
);

#[cfg(feature = "sqlite")]
fn open_proxy_ro(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("opening proxy.db {}: {e}", path.display()))
}

#[cfg(feature = "sqlite")]
fn sniff_proxy_db(path: &Path) -> u8 {
    let Ok(conn) = open_proxy_ro(path) else {
        return 0;
    };
    u8::from(
        has_sqlite_table(&conn, "conversations")
            && (has_sqlite_table(&conn, "items") || has_sqlite_table(&conn, "messages")),
    ) * 98
}

#[cfg(feature = "sqlite")]
fn sql_provider_predicate(cols: &[String], filter: ProviderFilter) -> Option<String> {
    let has_sp = cols.iter().any(|c| c == "source_provider");
    match filter {
        ProviderFilter::NativeProxy => {
            if has_sp {
                Some(
                    "LOWER(COALESCE(NULLIF(TRIM(CAST(c.source_provider AS TEXT)), ''), 'proxy')) = 'proxy'"
                        .to_string(),
                )
            } else {
                Some("1 = 1".to_string())
            }
        }
        ProviderFilter::External(providers) => {
            if !has_sp || providers.is_empty() {
                return None;
            }
            let quoted: Vec<String> = providers
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''").to_ascii_lowercase()))
                .collect();
            Some(format!(
                "LOWER(TRIM(CAST(c.source_provider AS TEXT))) IN ({})",
                quoted.join(", ")
            ))
        }
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn proxy_db_has_provider(
    data_root: Option<&Path>,
    providers: &'static [&'static str],
) -> bool {
    let Some(db_path) = resolve_proxy_db_path(data_root).filter(|p| p.is_file()) else {
        return false;
    };
    let Ok(conn) = open_proxy_ro(&db_path) else {
        return false;
    };
    if !has_sqlite_table(&conn, "conversations") {
        return false;
    }
    let cols = sqlite_table_columns(&conn, "conversations");
    let Some(pred) = sql_provider_predicate(&cols, ProviderFilter::External(providers)) else {
        return false;
    };
    let arch = if cols.iter().any(|c| c == "archived") {
        "COALESCE(c.archived, 0) = 0 AND "
    } else {
        ""
    };
    let sql = format!("SELECT 1 FROM conversations c WHERE {arch}{pred} LIMIT 1");
    conn.query_row(&sql, [], |_| Ok(true)).unwrap_or(false)
}

#[cfg(feature = "sqlite")]
pub(crate) fn parse_optional_mesh_proxy_db(
    data_root: Option<&Path>,
    spec: &ProxyDbAdapterSpec,
    selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    let Some(db_path) = resolve_proxy_db_path(data_root).filter(|p| p.is_file()) else {
        return Ok(Vec::new());
    };
    if sniff_proxy_db(&db_path) == 0 {
        return Ok(Vec::new());
    }
    parse_proxy_db_for_spec(&db_path, spec, selected)
}

#[cfg(feature = "sqlite")]
pub(crate) fn parse_proxy_db_for_spec(
    path: &Path,
    spec: &ProxyDbAdapterSpec,
    selected: Option<&HashSet<String>>,
) -> Result<Vec<ImportedConversation>, String> {
    let db_path = if path.is_dir() {
        path.join("proxy.db")
    } else {
        path.to_path_buf()
    };
    let fallback_ts = file_mtime_secs(&db_path);
    let conn = open_proxy_ro(&db_path)?;
    if !has_sqlite_table(&conn, "conversations") {
        return Ok(Vec::new());
    }

    let cols = sqlite_table_columns(&conn, "conversations");
    let Some(provider_pred) = sql_provider_predicate(&cols, spec.filter) else {
        return Ok(Vec::new());
    };
    let arch_pred = if cols.iter().any(|c| c == "archived") {
        "COALESCE(c.archived, 0) = 0 AND "
    } else {
        ""
    };
    let kind_expr = if cols.iter().any(|c| c == "kind") {
        "CAST(c.kind AS TEXT)"
    } else {
        "'direct'"
    };
    let sql = format!(
        "SELECT CAST(c.id AS TEXT), {}, {}, {kind_expr}, {}, {}
         FROM conversations c WHERE {arch_pred}{provider_pred} ORDER BY c.rowid ASC",
        sqlite_opt_col(
            &cols,
            &["source_id", "source_session_id", "external_id"],
            "c."
        ),
        sqlite_opt_col(&cols, &["title"], "c."),
        sqlite_opt_col(&cols, &["created_at"], "c."),
        sqlite_opt_col(&cols, &["updated_at"], "c."),
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("preparing conversations query: {e}"))?;
    let convs: Vec<ConvRow> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .map_err(|e| format!("querying conversations: {e}"))?
        .filter_map(Result::ok)
        .collect();

    let mut part_stmt = prepare_participants_stmt(&conn);
    let mut items_stmt = prepare_turns_stmt(&conn, "items")?;
    let mut msgs_stmt = prepare_turns_stmt(&conn, "messages")?;

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (cid, ext_sid, raw_title, kind_opt, created_raw, updated_raw) in convs {
        let source_id = (spec.make_source_id)(&cid, ext_sid.as_deref());
        if selected.is_some_and(|ids| !ids.contains(&source_id)) || !seen.insert(source_id.clone())
        {
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
        let participants = part_stmt
            .as_mut()
            .map(|st| query_participants(st, &cid))
            .unwrap_or_default();
        let scope = if spec.fixed_owner_scope {
            "owner".to_string()
        } else {
            resolve_scope(&cid, &kind, &participants)
        };

        let mut turns = match items_stmt.as_mut() {
            Some(st) => query_turns(st, &cid, created_at)?,
            None => Vec::new(),
        };
        if turns.is_empty()
            && let Some(st) = msgs_stmt.as_mut()
        {
            turns = query_turns(st, &cid, created_at)?;
        }
        if turns.is_empty() {
            continue;
        }
        let default_title = if spec.default_title.is_empty() {
            cid.as_str()
        } else {
            spec.default_title
        };
        let resolved_participants = if participants.is_empty() {
            spec.default_participants
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            participants
        };
        out.push(ImportedConversation::from_turns(
            source_id,
            spec.adapter_id,
            raw_title.as_deref(),
            default_title,
            scope,
            created_at,
            updated_at,
            resolved_participants,
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
fn prepare_participants_stmt(conn: &Connection) -> Option<Statement<'_>> {
    if !has_sqlite_table(conn, "conversation_participants") {
        return None;
    }
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
    conn.prepare(&sql).ok()
}

#[cfg(feature = "sqlite")]
fn query_participants(stmt: &mut Statement<'_>, cid: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rows) = stmt.query_map(params![cid], |r| r.get::<_, String>(0)) {
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
fn prepare_turns_stmt<'a>(
    conn: &'a Connection,
    table: &str,
) -> Result<Option<Statement<'a>>, String> {
    if !has_sqlite_table(conn, table) {
        return Ok(None);
    }
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
    conn.prepare(&sql)
        .map(Some)
        .map_err(|e| format!("preparing {table} turns query: {e}"))
}

#[cfg(feature = "sqlite")]
fn query_turns(
    stmt: &mut Statement<'_>,
    cid: &str,
    default_ts: u64,
) -> Result<Vec<ImportedTurn>, String> {
    let rows = stmt
        .query_map(params![cid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|e| format!("querying turns for {cid}: {e}"))?;
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
