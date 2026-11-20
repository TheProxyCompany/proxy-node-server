//! Open-source external chat history import interface ([`ChatImportAdapter`]),
//! registry ([`ChatImportRegistry`]), inventory scanners, and live job progress
//! state ([`ImportJobTracker`]).

pub mod adapters;
pub mod jobs;
pub mod util;

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub use jobs::{
    CONV_STATUS_DONE, CONV_STATUS_FAILED, CONV_STATUS_IMPORTING, CONV_STATUS_QUEUED,
    CONV_STATUS_SKIPPED, ConversationProgressState, ImportJobSnapshot, ImportJobTracker,
    JOB_STATUS_CANCELLED, JOB_STATUS_COMPLETED, JOB_STATUS_FAILED, JOB_STATUS_RUNNING,
};
pub use util::{
    SNIFF_HEAD_BYTES, collect_files_bounded, extract_value_text, fallback_title, file_mtime_secs,
    normalize_role, parse_timestamp_secs, parse_timestamp_str, preview_from_turns, read_sniff_head,
    sanitize_slug, stable_hash_hex, truncate_chars, unix_now_ms, user_home_dir,
};

pub const CHATGPT_ADAPTER_ID: &str = "chatgpt";
pub const CLAUDE_EXPORT_ADAPTER_ID: &str = "claude_export";
pub const CLAUDE_CODE_ADAPTER_ID: &str = "claude_code";
pub const CODEX_ADAPTER_ID: &str = "codex";
pub const HERMES_ADAPTER_ID: &str = "hermes";
pub const PROXY_THREADS_ADAPTER_ID: &str = "proxy_threads";
pub const MARKDOWN_JSONL_ADAPTER_ID: &str = "markdown_jsonl";

/// Classification of where a [`ChatImportAdapter`] reads chat history from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatImportSourceKind {
    LocalStore,
    ExportFile,
}

impl ChatImportSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalStore => "local_store",
            Self::ExportFile => "export_file",
        }
    }
}

impl fmt::Display for ChatImportSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<ChatImportSourceKind> for String {
    fn from(kind: ChatImportSourceKind) -> Self {
        kind.as_str().to_string()
    }
}

impl FromStr for ChatImportSourceKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local_store" => Ok(Self::LocalStore),
            "export_file" => Ok(Self::ExportFile),
            other => Err(format!("unknown chat import source kind: {other}")),
        }
    }
}

/// UI and discovery metadata describing a [`ChatImportAdapter`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatImportAdapterDescriptor {
    pub adapter_id: String,
    pub display_name: String,
    pub subtitle: String,
    pub export_hint: String,
    pub icon_name: String,
    pub source_kind: String,
    pub extensions: Vec<String>,
    #[serde(default)]
    pub brand_id: String,
    #[serde(default)]
    pub default_agent_id: String,
}

/// Canonical normalized turn within an imported conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedTurn {
    pub role: String,
    pub content: String,
    pub timestamp: u64,
}

/// Lightweight per-conversation manifest omitting turn bodies for instant UI inventory scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationManifest {
    pub source_id: String,
    pub adapter_id: String,
    pub title: String,
    pub scope: String,
    pub message_count: usize,
    pub user_message_count: usize,
    pub assistant_message_count: usize,
    pub created_at: u64,
    pub updated_at: u64,
    pub preview: String,
    pub participants: Vec<String>,
}

/// Full normalized conversation ready for agent memory ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedConversation {
    pub source_id: String,
    pub adapter_id: String,
    pub title: String,
    pub scope: String,
    pub message_count: usize,
    pub user_message_count: usize,
    pub assistant_message_count: usize,
    pub created_at: u64,
    pub updated_at: u64,
    pub preview: String,
    pub participants: Vec<String>,
    pub turns: Vec<ImportedTurn>,
}

impl ImportedConversation {
    /// Construct an [`ImportedConversation`] from turns, deriving message counts,
    /// preview text, fallback title, and bounded timestamps automatically.
    #[allow(clippy::too_many_arguments)]
    pub fn from_turns(
        source_id: String,
        adapter_id: &str,
        raw_title: Option<&str>,
        default_title: &str,
        scope: String,
        created_at: u64,
        updated_at: u64,
        participants: Vec<String>,
        turns: Vec<ImportedTurn>,
    ) -> Self {
        let message_count = turns.len();
        let user_message_count = turns.iter().filter(|t| t.role == "user").count();
        let assistant_message_count = turns.iter().filter(|t| t.role == "assistant").count();
        let min_ts = turns
            .iter()
            .map(|t| t.timestamp)
            .min()
            .unwrap_or(created_at);
        let max_ts = turns
            .iter()
            .map(|t| t.timestamp)
            .max()
            .unwrap_or(updated_at);
        let resolved_created = if created_at == 0 { min_ts } else { created_at };
        let resolved_updated = updated_at.max(max_ts).max(resolved_created);
        let title = fallback_title(raw_title, &turns, default_title);
        let preview = preview_from_turns(&turns);

        Self {
            source_id,
            adapter_id: adapter_id.to_string(),
            title,
            scope,
            message_count,
            user_message_count,
            assistant_message_count,
            created_at: resolved_created,
            updated_at: resolved_updated,
            preview,
            participants,
            turns,
        }
    }

    /// Project a lightweight [`ConversationManifest`] without copying `turns`.
    pub fn summary(&self) -> ConversationManifest {
        ConversationManifest {
            source_id: self.source_id.clone(),
            adapter_id: self.adapter_id.clone(),
            title: self.title.clone(),
            scope: self.scope.clone(),
            message_count: self.message_count,
            user_message_count: self.user_message_count,
            assistant_message_count: self.assistant_message_count,
            created_at: self.created_at,
            updated_at: self.updated_at,
            preview: self.preview.clone(),
            participants: self.participants.clone(),
        }
    }
}

/// Lightweight per-adapter summary returned by [`ChatImportRegistry::overview`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterOverview {
    pub descriptor: ChatImportAdapterDescriptor,
    pub source_path: Option<String>,
    pub available: bool,
    pub conversation_count: usize,
    pub total_message_count: usize,
}

/// Detailed adapter inventory with per-conversation manifests for selective import UIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterInventory {
    pub descriptor: ChatImportAdapterDescriptor,
    pub source_path: Option<String>,
    pub available: bool,
    pub conversation_count: usize,
    pub total_message_count: usize,
    pub conversations: Vec<ConversationManifest>,
}

/// Pluggable open-source adapter for discovering, sniffing, and parsing chat histories.
pub trait ChatImportAdapter: Send + Sync {
    /// Static UI and file-picker metadata for this adapter.
    fn descriptor(&self) -> ChatImportAdapterDescriptor;

    /// Default local store path on disk when `source_kind == "local_store"`.
    fn default_local_path(&self, _data_root: Option<&Path>) -> Option<PathBuf> {
        None
    }

    /// Resolve `(source_path, available)` for automatic local discovery or an explicit `custom_path`.
    fn resolve_source(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
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
        let Some(local) = self.default_local_path(data_root) else {
            return Ok((None, false));
        };
        let available = local.exists();
        Ok((Some(local.to_string_lossy().into_owned()), available))
    }

    /// Return a confidence score in `0..=100` for whether `path` belongs to this adapter.
    fn sniff(&self, path: &Path, head: &[u8]) -> u8;

    /// Parse all conversations found at `path`.
    fn parse_conversations(&self, path: &Path) -> Result<Vec<ImportedConversation>, String>;

    /// Scan lightweight conversation manifests without retaining turn bodies.
    fn scan_manifests(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
    ) -> Result<Vec<ConversationManifest>, String> {
        let target = resolve_adapter_target(self, custom_path, data_root)?;
        Ok(self
            .parse_conversations(&target)?
            .iter()
            .map(ImportedConversation::summary)
            .collect())
    }

    /// Lightweight `(conversation_count, total_message_count)` scan for `overview()`.
    fn overview_counts(&self, data_root: Option<&Path>) -> Result<(usize, usize), String> {
        let manifests = self.scan_manifests(None, data_root)?;
        Ok((
            manifests.len(),
            manifests.iter().map(|m| m.message_count).sum(),
        ))
    }

    /// Load conversations from `custom_path` or local/mesh stores, optionally filtering to `selected_ids`.
    fn load_conversations(
        &self,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
        selected_ids: Option<&HashSet<String>>,
    ) -> Result<Vec<ImportedConversation>, String> {
        let target = resolve_adapter_target(self, custom_path, data_root)?;
        let mut convs = self.parse_conversations(&target)?;
        if let Some(selected) = selected_ids {
            convs.retain(|c| selected.contains(&c.source_id));
        }
        Ok(convs)
    }
}

fn resolve_adapter_target<A: ChatImportAdapter + ?Sized>(
    adapter: &A,
    custom_path: Option<&Path>,
    data_root: Option<&Path>,
) -> Result<PathBuf, String> {
    let target = custom_path
        .map(Path::to_path_buf)
        .or_else(|| adapter.default_local_path(data_root))
        .ok_or_else(|| {
            format!(
                "adapter '{}' requires an explicit file path",
                adapter.descriptor().adapter_id
            )
        })?;
    if !target.exists() {
        return Err(format!("import path does not exist: {}", target.display()));
    }
    Ok(target)
}

/// Extensible registry of [`ChatImportAdapter`] implementations.
pub struct ChatImportRegistry {
    adapters: Vec<Box<dyn ChatImportAdapter>>,
}

impl Default for ChatImportRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl ChatImportRegistry {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Construct a registry pre-populated with all 7 first-class built-in adapters.
    pub fn builtin() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(adapters::chatgpt::ChatGptAdapter));
        reg.register(Box::new(adapters::claude_export::ClaudeExportAdapter));
        reg.register(Box::new(adapters::claude_code::ClaudeCodeAdapter));
        reg.register(Box::new(adapters::codex::CodexAdapter));
        reg.register(Box::new(adapters::hermes::HermesAdapter));
        reg.register(Box::new(adapters::proxy_threads::ProxyThreadsAdapter));
        reg.register(Box::new(adapters::markdown_jsonl::MarkdownJsonlAdapter));
        reg
    }

    /// Register or replace an adapter with matching `adapter_id`.
    pub fn register(&mut self, adapter: Box<dyn ChatImportAdapter>) {
        let id = adapter.descriptor().adapter_id;
        if let Some(pos) = self
            .adapters
            .iter()
            .position(|existing| existing.descriptor().adapter_id == id)
        {
            self.adapters[pos] = adapter;
        } else {
            self.adapters.push(adapter);
        }
    }

    /// Return descriptors for all registered adapters in registration order.
    pub fn descriptors(&self) -> Vec<ChatImportAdapterDescriptor> {
        self.adapters.iter().map(|a| a.descriptor()).collect()
    }

    /// Look up a registered adapter by `adapter_id` (case-insensitive).
    pub fn get(&self, adapter_id: &str) -> Option<&dyn ChatImportAdapter> {
        let needle = adapter_id.trim();
        self.adapters
            .iter()
            .find(|a| a.descriptor().adapter_id.eq_ignore_ascii_case(needle))
            .map(Box::as_ref)
    }

    /// Sniff `path` across all registered adapters and return the highest-confidence match.
    pub fn detect(&self, path: &Path) -> Option<(&dyn ChatImportAdapter, u8)> {
        let head = read_sniff_head(path).unwrap_or_default();
        let mut best: Option<(&dyn ChatImportAdapter, u8)> = None;
        for adapter in &self.adapters {
            let score = adapter.sniff(path, &head).min(100);
            if score == 0 {
                continue;
            }
            if best.is_none_or(|(_, top)| score > top) {
                best = Some((adapter.as_ref(), score));
            }
        }
        best
    }

    /// Check local/mesh store availability for every registered adapter and scan lightweight counts.
    pub fn overview(&self, data_root: Option<&Path>) -> Vec<AdapterOverview> {
        self.adapters
            .iter()
            .map(|adapter| {
                let descriptor = adapter.descriptor();
                let (source_path, available) = adapter
                    .resolve_source(None, data_root)
                    .unwrap_or((None, false));
                if !available {
                    return AdapterOverview {
                        descriptor,
                        source_path,
                        available: false,
                        conversation_count: 0,
                        total_message_count: 0,
                    };
                }
                match adapter.overview_counts(data_root) {
                    Ok((conversation_count, total_message_count)) => AdapterOverview {
                        descriptor,
                        source_path,
                        available: true,
                        conversation_count,
                        total_message_count,
                    },
                    Err(_) => AdapterOverview {
                        descriptor,
                        source_path,
                        available: false,
                        conversation_count: 0,
                        total_message_count: 0,
                    },
                }
            })
            .collect()
    }

    /// Scan per-conversation manifests and message counts for a single adapter.
    pub fn scan_adapter(
        &self,
        adapter_id: &str,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
    ) -> Result<AdapterInventory, String> {
        let adapter = self
            .get(adapter_id)
            .ok_or_else(|| format!("unknown chat import adapter: {adapter_id}"))?;
        let descriptor = adapter.descriptor();
        let (source_path, available) = adapter.resolve_source(custom_path, data_root)?;
        if !available {
            return Ok(AdapterInventory {
                descriptor,
                source_path,
                available: false,
                conversation_count: 0,
                total_message_count: 0,
                conversations: Vec::new(),
            });
        }
        let mut conversations = adapter.scan_manifests(custom_path, data_root)?;
        conversations.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
        let conversation_count = conversations.len();
        let total_message_count = conversations.iter().map(|c| c.message_count).sum();
        Ok(AdapterInventory {
            descriptor,
            source_path,
            available: true,
            conversation_count,
            total_message_count,
            conversations,
        })
    }

    /// Load full [`ImportedConversation`] turns for `adapter_id`, optionally filtered to `selected_ids`.
    pub fn load_conversations(
        &self,
        adapter_id: &str,
        custom_path: Option<&Path>,
        data_root: Option<&Path>,
        selected_ids: Option<&HashSet<String>>,
    ) -> Result<Vec<ImportedConversation>, String> {
        let adapter = self
            .get(adapter_id)
            .ok_or_else(|| format!("unknown chat import adapter: {adapter_id}"))?;
        let mut convs = adapter.load_conversations(custom_path, data_root, selected_ids)?;
        if let Some(selected) = selected_ids {
            convs.retain(|c| selected.contains(&c.source_id));
        }
        convs.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
        Ok(convs)
    }
}
