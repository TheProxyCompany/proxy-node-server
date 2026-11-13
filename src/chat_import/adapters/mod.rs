//! Built-in [`crate::chat_import::ChatImportAdapter`] implementations, pure-Rust PKZIP
//! reader, and SQLite introspection helpers.

pub mod chatgpt;
pub mod claude_code;
pub mod claude_export;
pub mod codex;
pub mod hermes;
pub mod markdown_jsonl;
pub mod proxy_threads;

use std::io::Read;

use flate2::read::DeflateDecoder;

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
