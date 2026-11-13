//! Shared deterministic hashing, timestamp normalization, file traversal, and text helpers
//! for [`crate::chat_import`] adapters.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::ImportedTurn;

pub const SNIFF_HEAD_BYTES: usize = 16 * 1024;

/// Read up to [`SNIFF_HEAD_BYTES`] from a file for fast format detection.
pub fn read_sniff_head(path: &Path) -> Result<Vec<u8>, String> {
    if path.is_dir() {
        return Ok(Vec::new());
    }
    let mut file = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut buf = vec![0u8; SNIFF_HEAD_BYTES];
    let n = file
        .read(&mut buf)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    buf.truncate(n);
    Ok(buf)
}

/// Collect regular files recursively up to `max_depth`, sorted deterministically.
pub fn collect_files_bounded(
    dir: &Path,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if max_depth == 0 || !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("reading directory {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for entry in entries {
        let name = entry
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if name.starts_with('.') && name != ".claude" && name != ".codex" && name != ".hermes" {
            continue;
        }
        if entry.is_dir() {
            collect_files_bounded(&entry, max_depth - 1, out)?;
        } else if entry.is_file() {
            out.push(entry);
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
thread_local! {
    static TEST_HOME_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, feature = "sqlite"))]
pub(crate) fn with_test_home_dir<T>(home: &Path, f: impl FnOnce() -> T) -> T {
    struct Guard(Option<PathBuf>);
    impl Drop for Guard {
        fn drop(&mut self) {
            let prev = self.0.take();
            TEST_HOME_DIR.with(|slot| *slot.borrow_mut() = prev);
        }
    }
    let prev = TEST_HOME_DIR.with(|slot| slot.borrow_mut().replace(home.to_path_buf()));
    let _guard = Guard(prev);
    f()
}

/// Resolve the current user's home directory from `HOME` or `USERPROFILE`.
pub fn user_home_dir() -> Option<PathBuf> {
    #[cfg(all(test, feature = "sqlite"))]
    if let Some(overridden) = TEST_HOME_DIR.with(|slot| slot.borrow().clone()) {
        return Some(overridden);
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Current UNIX epoch timestamp in milliseconds.
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deterministic 24-hex-char SHA-256 prefix for stable synthetic source IDs.
pub fn stable_hash_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut s = String::with_capacity(24);
    for b in &digest[..12] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Sanitize an arbitrary path or filename stem into a clean lowercase slug.
pub fn sanitize_slug(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Normalize heterogeneous speaker role strings into canonical `"user"`, `"assistant"`, `"tool"`, or `"system"`.
pub fn normalize_role(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "user" | "human" | "owner" | "person" | "self" => "user".to_string(),
        "assistant" | "model" | "ai" | "bot" | "agent" | "talk" | "claude" | "chatgpt"
        | "codex" => "assistant".to_string(),
        "tool" | "function" | "tool_result" | "echo" => "tool".to_string(),
        "system" | "developer" | "note" => "system".to_string(),
        other if !other.is_empty() => other.to_string(),
        _ => "user".to_string(),
    }
}

/// Parse a JSON timestamp value (seconds, milliseconds, microseconds, float, or ISO-8601 string) into UNIX seconds.
pub fn parse_timestamp_secs(val: Option<&Value>) -> Option<u64> {
    let v = val?;
    if let Some(n) = v.as_u64() {
        return Some(normalize_epoch_units(n));
    }
    if let Some(f) = v.as_f64()
        && f.is_finite()
        && f > 0.0
    {
        return Some(normalize_epoch_units(f as u64));
    }
    if let Some(s) = v.as_str() {
        return parse_timestamp_str(s);
    }
    None
}

/// Parse a numeric or ISO-8601 / RFC-3339 / SQLite datetime string into UNIX seconds.
pub fn parse_timestamp_str(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(n) = trimmed.parse::<u64>() {
        return Some(normalize_epoch_units(n));
    }
    if let Ok(f) = trimmed.parse::<f64>()
        && f.is_finite()
        && f > 0.0
    {
        return Some(normalize_epoch_units(f as u64));
    }
    parse_iso8601_secs(trimmed)
}

fn normalize_epoch_units(raw: u64) -> u64 {
    if raw > 100_000_000_000_000 {
        raw / 1_000_000
    } else if raw > 100_000_000_000 {
        raw / 1_000
    } else {
        raw
    }
}

fn parse_iso8601_secs(s: &str) -> Option<u64> {
    if s.len() < 10 {
        return None;
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if s.len() == 10 {
        return u64::try_from((days * 86_400).max(0)).ok();
    }
    let sep = b[10];
    if sep != b'T' && sep != b't' && sep != b' ' {
        return u64::try_from((days * 86_400).max(0)).ok();
    }
    let rest = s.get(11..)?.trim();
    if rest.len() < 8 || rest.as_bytes()[2] != b':' || rest.as_bytes()[5] != b':' {
        return None;
    }
    let hour: i64 = rest.get(0..2)?.parse().ok()?;
    let min: i64 = rest.get(3..5)?.parse().ok()?;
    let sec: i64 = rest.get(6..8)?.parse().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=60).contains(&sec) {
        return None;
    }
    let mut tail = rest.get(8..).unwrap_or_default().trim();
    if let Some(after_dot) = tail.strip_prefix('.') {
        let frac_len = after_dot.bytes().take_while(|c| c.is_ascii_digit()).count();
        tail = after_dot.get(frac_len..).unwrap_or_default().trim();
    }
    let tz_offset_secs = parse_tz_offset_secs(tail)?;
    let epoch = days * 86_400 + hour * 3_600 + min * 60 + sec - tz_offset_secs;
    u64::try_from(epoch.max(0)).ok()
}

fn parse_tz_offset_secs(tail: &str) -> Option<i64> {
    if tail.is_empty() || tail.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let sign = match tail.as_bytes().first()? {
        b'+' => 1_i64,
        b'-' => -1_i64,
        _ => return None,
    };
    let digits = &tail[1..];
    let (hh, mm) = if let Some((h, m)) = digits.split_once(':') {
        (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
    } else if digits.len() == 4 {
        (
            digits[0..2].parse::<i64>().ok()?,
            digits[2..4].parse::<i64>().ok()?,
        )
    } else if digits.len() == 2 {
        (digits.parse::<i64>().ok()?, 0)
    } else {
        return None;
    };
    Some(sign * (hh * 3_600 + mm * 60))
}

/// Howard Hinnant's civil-date-to-days-since-1970-01-01 algorithm.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let m = i64::from(month);
    let d = i64::from(day);
    let y = year - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Best-effort file modification timestamp in UNIX seconds.
pub fn file_mtime_secs(path: &Path) -> u64 {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(|| unix_now_ms() / 1_000)
}

/// Recursively extract plain text from nested JSON message structures.
pub fn extract_value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.trim().to_string(),
        Value::Array(items) => items
            .iter()
            .map(extract_value_text)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(map) => {
            if let Some(parts) = map.get("parts") {
                let text = extract_value_text(parts);
                if !text.is_empty() {
                    return text;
                }
            }
            for key in ["text", "content", "value", "body", "result", "output"] {
                if let Some(inner) = map.get(key) {
                    let text = extract_value_text(inner);
                    if !text.is_empty() {
                        return text;
                    }
                }
            }
            String::new()
        }
        _ => String::new(),
    }
}

/// Derive a clean human-readable conversation title from explicit title or first turn.
pub fn fallback_title(raw_title: Option<&str>, turns: &[ImportedTurn], fallback: &str) -> String {
    if let Some(t) = raw_title.map(str::trim).filter(|s| !s.is_empty()) {
        return truncate_chars(t, 120);
    }
    if let Some(first) = turns
        .iter()
        .find(|t| t.role == "user" && !t.content.trim().is_empty())
        .or_else(|| turns.iter().find(|t| !t.content.trim().is_empty()))
    {
        let single_line = first
            .content
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or(fallback);
        return truncate_chars(single_line, 96);
    }
    fallback.to_string()
}

/// Derive a compact single-line preview snippet from conversation turns.
pub fn preview_from_turns(turns: &[ImportedTurn]) -> String {
    let Some(chosen) = turns
        .iter()
        .find(|t| t.role == "user" && !t.content.trim().is_empty())
        .or_else(|| turns.iter().find(|t| !t.content.trim().is_empty()))
    else {
        return String::new();
    };
    let collapsed = chosen
        .content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    truncate_chars(&collapsed, 160)
}

/// Truncate a string on a UTF-8 character boundary, appending `"..."` if truncated.
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let taken: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}...", taken.trim_end())
    } else {
        taken
    }
}
