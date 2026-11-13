//! Built-in [`crate::chat_import::ChatImportAdapter`] implementations, pure-Rust PKZIP
//! reader, and SQLite introspection helpers.

pub mod chatgpt;
pub mod claude_code;
pub mod claude_export;
pub mod codex;
pub mod hermes;
pub mod markdown_jsonl;
pub mod proxy_threads;

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::DeflateDecoder;

use crate::chat_import::{
    CLAUDE_CODE_ADAPTER_ID, CODEX_ADAPTER_ID, ConversationManifest, HERMES_ADAPTER_ID,
    ImportedConversation, PROXY_THREADS_ADAPTER_ID,
};

#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) enum ProviderFilter {
    NativeProxy,
    External(&'static [&'static str]),
}

#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) struct ProxyDbAdapterSpec {
    pub adapter_id: &'static str,
    pub filter: ProviderFilter,
    pub default_title: &'static str,
    pub default_participants: &'static [&'static str],
    pub fixed_owner_scope: bool,
    pub make_source_id: fn(&str, Option<&str>) -> String,
}

fn strip_ext_id<'a>(cid: &'a str, ext_sid: Option<&'a str>, prefixes: &[&str]) -> &'a str {
    let raw = ext_sid
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| cid.trim());
    for p in prefixes {
        if let Some(rest) = raw.strip_prefix(p) {
            return rest;
        }
    }
    raw
}

fn proxy_native_source_id(cid: &str, _: Option<&str>) -> String {
    format!("proxy_threads:{cid}")
}

fn hermes_proxy_source_id(cid: &str, ext_sid: Option<&str>) -> String {
    let raw = ext_sid
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| cid.trim());
    if raw.starts_with("hermes:session:") || raw.starts_with("hermes:facts:") {
        return raw.to_string();
    }
    let s = strip_ext_id(cid, ext_sid, &["hermes:", "hermes-agent:", "ext.hermes."]);
    format!("hermes:session:{s}")
}

fn claude_code_proxy_source_id(cid: &str, ext_sid: Option<&str>) -> String {
    let s = strip_ext_id(
        cid,
        ext_sid,
        &[
            "claude_code:",
            "claude-code:",
            "ext.claude_code.",
            "ext.claude-code.",
        ],
    );
    format!("claude_code:{s}")
}

fn codex_proxy_source_id(cid: &str, ext_sid: Option<&str>) -> String {
    let s = strip_ext_id(cid, ext_sid, &["codex:", "ext.codex."]);
    format!("codex:{s}")
}

pub(crate) const HERMES_PROVIDERS: &[&str] = &["hermes", "hermes-agent"];
pub(crate) const CLAUDE_CODE_PROVIDERS: &[&str] = &["claude_code", "claude-code"];
pub(crate) const CODEX_PROVIDERS: &[&str] = &["codex"];

pub(crate) const PROXY_NATIVE_SPEC: ProxyDbAdapterSpec = ProxyDbAdapterSpec {
    adapter_id: PROXY_THREADS_ADAPTER_ID,
    filter: ProviderFilter::NativeProxy,
    default_title: "",
    default_participants: &["owner", "Proxy"],
    fixed_owner_scope: false,
    make_source_id: proxy_native_source_id,
};

pub(crate) const HERMES_MESH_SPEC: ProxyDbAdapterSpec = ProxyDbAdapterSpec {
    adapter_id: HERMES_ADAPTER_ID,
    filter: ProviderFilter::External(HERMES_PROVIDERS),
    default_title: "Hermes Session",
    default_participants: &["user", "Hermes"],
    fixed_owner_scope: true,
    make_source_id: hermes_proxy_source_id,
};

pub(crate) const CLAUDE_CODE_MESH_SPEC: ProxyDbAdapterSpec = ProxyDbAdapterSpec {
    adapter_id: CLAUDE_CODE_ADAPTER_ID,
    filter: ProviderFilter::External(CLAUDE_CODE_PROVIDERS),
    default_title: "Claude Code Session",
    default_participants: &["user", "Claude Code"],
    fixed_owner_scope: true,
    make_source_id: claude_code_proxy_source_id,
};

pub(crate) const CODEX_MESH_SPEC: ProxyDbAdapterSpec = ProxyDbAdapterSpec {
    adapter_id: CODEX_ADAPTER_ID,
    filter: ProviderFilter::External(CODEX_PROVIDERS),
    default_title: "Codex Session",
    default_participants: &["user", "Codex"],
    fixed_owner_scope: true,
    make_source_id: codex_proxy_source_id,
};

/// Extract matching entries from a standard PKZIP archive (`Store` = 0, `Deflate` = 8)
/// by walking the Central Directory.
pub fn read_zip_entries<F>(
    bytes: &[u8],
    mut accept_name: F,
) -> Result<Vec<(String, Vec<u8>)>, String>
where
    F: FnMut(&str) -> bool,
{
    const EOCD_SIG: u32 = 0x0605_4b50;
    const CEN_SIG: u32 = 0x0201_4b50;
    const LOC_SIG: u32 = 0x0403_4b50;

    if bytes.len() < 22 || &bytes[..4] != b"PK\x03\x04" {
        return Err("not a valid PKZIP archive".to_string());
    }
    let min_eocd = bytes.len().saturating_sub(65_557);
    let mut eocd_pos = None;
    for pos in (min_eocd..=bytes.len() - 22).rev() {
        if u32_le(bytes, pos) == EOCD_SIG {
            eocd_pos = Some(pos);
            break;
        }
    }
    let eocd = eocd_pos.ok_or_else(|| "ZIP central directory footer not found".to_string())?;
    let total_entries = u16_le(bytes, eocd + 10) as usize;
    let cd_size = u32_le(bytes, eocd + 12) as usize;
    let cd_offset = u32_le(bytes, eocd + 16) as usize;
    if cd_offset.saturating_add(cd_size) > bytes.len() {
        return Err("ZIP central directory out of bounds".to_string());
    }

    let mut out = Vec::new();
    let mut cursor = cd_offset;
    for _ in 0..total_entries {
        if cursor + 46 > bytes.len() || u32_le(bytes, cursor) != CEN_SIG {
            break;
        }
        let method = u16_le(bytes, cursor + 10);
        let comp_size = u32_le(bytes, cursor + 20) as usize;
        let uncomp_size = u32_le(bytes, cursor + 24) as usize;
        let name_len = u16_le(bytes, cursor + 28) as usize;
        let extra_len = u16_le(bytes, cursor + 30) as usize;
        let comment_len = u16_le(bytes, cursor + 32) as usize;
        let local_offset = u32_le(bytes, cursor + 42) as usize;

        let name_end = cursor + 46 + name_len;
        if name_end > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[cursor + 46..name_end]).into_owned();
        cursor = name_end + extra_len + comment_len;

        if name.ends_with('/') || !accept_name(&name) {
            continue;
        }
        if local_offset + 30 > bytes.len() || u32_le(bytes, local_offset) != LOC_SIG {
            return Err(format!("invalid ZIP local header for {name}"));
        }
        let loc_name_len = u16_le(bytes, local_offset + 26) as usize;
        let loc_extra_len = u16_le(bytes, local_offset + 28) as usize;
        let data_start = local_offset + 30 + loc_name_len + loc_extra_len;
        let data_end = data_start.saturating_add(comp_size);
        if data_end > bytes.len() {
            return Err(format!("ZIP entry payload out of bounds for {name}"));
        }
        let slice = &bytes[data_start..data_end];
        let decoded = match method {
            0 => slice.to_vec(),
            8 => {
                let mut decoder = DeflateDecoder::new(slice);
                let mut buf = Vec::with_capacity(uncomp_size.min(64 * 1024 * 1024));
                decoder
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("decompressing {name}: {e}"))?;
                buf
            }
            other => {
                return Err(format!(
                    "unsupported ZIP compression method {other} for {name}"
                ));
            }
        };
        out.push((name, decoded));
    }
    Ok(out)
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(feature = "sqlite")]
pub(crate) fn has_sqlite_table(conn: &rusqlite::Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
        [name],
        |_| Ok(true),
    )
    .unwrap_or(false)
}

#[cfg(feature = "sqlite")]
pub(crate) fn sqlite_table_columns(conn: &rusqlite::Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .and_then(|mut st| {
            Ok(st
                .query_map([], |r| r.get::<_, String>(1))?
                .filter_map(Result::ok)
                .collect())
        })
        .unwrap_or_default()
}

#[cfg(feature = "sqlite")]
pub(crate) fn sqlite_opt_col(cols: &[String], candidates: &[&str], prefix: &str) -> String {
    candidates
        .iter()
        .find(|&&c| cols.iter().any(|existing| existing == c))
        .map(|c| {
            if prefix.is_empty() {
                format!("CAST(\"{c}\" AS TEXT)")
            } else {
                format!("CAST({prefix}\"{c}\" AS TEXT)")
            }
        })
        .unwrap_or_else(|| "NULL".to_string())
}

pub(crate) fn mesh_resolve_source(
    custom_path: Option<&Path>,
    local_default: Option<PathBuf>,
    data_root: Option<&Path>,
    providers: &'static [&'static str],
) -> Result<(Option<String>, bool), String> {
    if let Some(explicit) = custom_path {
        if !explicit.exists() {
            return Err(format!(
                "import path does not exist: {}",
                explicit.display()
            ));
        }
        return Ok((Some(explicit.to_string_lossy().into_owned()), true));
    }
    if let Some(ref local) = local_default
        && local.exists()
    {
        return Ok((Some(local.to_string_lossy().into_owned()), true));
    }
    if proxy_threads::proxy_db_has_provider(data_root, providers)
        && let Some(db) = proxy_threads::resolve_proxy_db_path(data_root)
    {
        return Ok((Some(db.to_string_lossy().into_owned()), true));
    }
    Ok((
        local_default.map(|p| p.to_string_lossy().into_owned()),
        false,
    ))
}

fn is_auto_or_default_target(
    custom_path: Option<&Path>,
    local_default: Option<&Path>,
    proxy_db: Option<&Path>,
) -> bool {
    custom_path.is_none()
        || (custom_path.is_some() && (custom_path == local_default || custom_path == proxy_db))
}

pub(crate) fn mesh_scan_manifests<F>(
    custom_path: Option<&Path>,
    local_default: Option<PathBuf>,
    data_root: Option<&Path>,
    providers: &'static [&'static str],
    spec: &ProxyDbAdapterSpec,
    scan_local: F,
) -> Result<Vec<ConversationManifest>, String>
where
    F: FnOnce(&Path) -> Result<Vec<ConversationManifest>, String>,
{
    let proxy_db = proxy_threads::resolve_proxy_db_path(data_root);
    if !is_auto_or_default_target(custom_path, local_default.as_deref(), proxy_db.as_deref()) {
        let explicit = custom_path.expect("checked non-none custom_path");
        if !explicit.exists() {
            return Err(format!(
                "import path does not exist: {}",
                explicit.display()
            ));
        }
        if proxy_threads::is_proxy_db_file(explicit) {
            return Ok(
                proxy_threads::parse_proxy_db_for_spec(explicit, spec, None)?
                    .iter()
                    .map(ImportedConversation::summary)
                    .collect(),
            );
        }
        return scan_local(explicit);
    }

    let local_existing = local_default.as_deref().filter(|p| p.exists());
    let has_mesh = proxy_threads::proxy_db_has_provider(data_root, providers);
    if local_existing.is_none() && !has_mesh {
        return match local_default {
            Some(p) => Err(format!("import path does not exist: {}", p.display())),
            None => Err(format!(
                "adapter '{}' requires an explicit file path",
                spec.adapter_id
            )),
        };
    }

    let (mut seen, mut out) = (HashSet::new(), Vec::new());
    if let Some(local_dir) = local_existing {
        for m in scan_local(local_dir)? {
            if seen.insert(m.source_id.clone()) {
                out.push(m);
            }
        }
    }
    if has_mesh {
        for c in proxy_threads::parse_optional_mesh_proxy_db(data_root, spec, None)? {
            if seen.insert(c.source_id.clone()) {
                out.push(c.summary());
            }
        }
    }
    Ok(out)
}

pub(crate) fn mesh_load_conversations<F>(
    custom_path: Option<&Path>,
    local_default: Option<PathBuf>,
    data_root: Option<&Path>,
    providers: &'static [&'static str],
    spec: &ProxyDbAdapterSpec,
    selected: Option<&HashSet<String>>,
    load_local: F,
) -> Result<Vec<ImportedConversation>, String>
where
    F: FnOnce(&Path, Option<&HashSet<String>>) -> Result<Vec<ImportedConversation>, String>,
{
    let proxy_db = proxy_threads::resolve_proxy_db_path(data_root);
    if !is_auto_or_default_target(custom_path, local_default.as_deref(), proxy_db.as_deref()) {
        let explicit = custom_path.expect("checked non-none custom_path");
        if !explicit.exists() {
            return Err(format!(
                "import path does not exist: {}",
                explicit.display()
            ));
        }
        if proxy_threads::is_proxy_db_file(explicit) {
            return proxy_threads::parse_proxy_db_for_spec(explicit, spec, selected);
        }
        let mut convs = load_local(explicit, selected)?;
        if let Some(sel) = selected {
            convs.retain(|c| sel.contains(&c.source_id));
        }
        return Ok(convs);
    }

    let local_existing = local_default.as_deref().filter(|p| p.exists());
    let has_mesh = proxy_threads::proxy_db_has_provider(data_root, providers);
    if local_existing.is_none() && !has_mesh {
        return match local_default {
            Some(p) => Err(format!("import path does not exist: {}", p.display())),
            None => Err(format!(
                "adapter '{}' requires an explicit file path",
                spec.adapter_id
            )),
        };
    }

    let (mut seen, mut out) = (HashSet::new(), Vec::new());
    if let Some(local_dir) = local_existing {
        for c in load_local(local_dir, selected)? {
            if selected.is_none_or(|s| s.contains(&c.source_id)) && seen.insert(c.source_id.clone())
            {
                out.push(c);
            }
        }
    }
    if has_mesh {
        for c in proxy_threads::parse_optional_mesh_proxy_db(data_root, spec, selected)? {
            if selected.is_none_or(|s| s.contains(&c.source_id)) && seen.insert(c.source_id.clone())
            {
                out.push(c);
            }
        }
    }
    Ok(out)
}
