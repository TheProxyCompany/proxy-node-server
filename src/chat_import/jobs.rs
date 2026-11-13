//! Thread-safe live import job progress tracker ([`ImportJobTracker`]) for per-agent
//! chat history ingestion, cancellation, and per-conversation status UI updates.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::ConversationManifest;
use super::util::unix_now_ms;

pub const JOB_STATUS_RUNNING: &str = "running";
pub const JOB_STATUS_COMPLETED: &str = "completed";
pub const JOB_STATUS_FAILED: &str = "failed";
pub const JOB_STATUS_CANCELLED: &str = "cancelled";

pub const CONV_STATUS_QUEUED: &str = "queued";
pub const CONV_STATUS_IMPORTING: &str = "importing";
pub const CONV_STATUS_DONE: &str = "done";
pub const CONV_STATUS_SKIPPED: &str = "skipped";
pub const CONV_STATUS_FAILED: &str = "failed";

const DEFAULT_MAX_TERMINAL_JOBS_PER_AGENT: usize = 32;

/// Per-conversation progress entry inside an [`ImportJobSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationProgressState {
    /// `"queued"` | `"importing"` | `"done"` | `"skipped"` | `"failed"`
    pub status: String,
    pub processed_messages: usize,
    pub total_messages: usize,
}

/// Point-in-time snapshot of an active or recently finished chat import job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportJobSnapshot {
    pub job_id: String,
    pub agent_id: String,
    pub adapter_id: String,
    pub adapter_name: String,
    pub source_path: Option<String>,
    /// `"running"` | `"completed"` | `"failed"` | `"cancelled"`
    pub status: String,
    pub total_conversations: usize,
    pub completed_conversations: usize,
    pub skipped_conversations: usize,
    pub total_messages: usize,
    pub processed_messages: usize,
    pub extracted_facts: usize,
    pub current_conversation_id: Option<String>,
    pub current_conversation_title: Option<String>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub error: Option<String>,
    pub conversation_states: BTreeMap<String, ConversationProgressState>,
}

impl ImportJobSnapshot {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status.as_str(),
            JOB_STATUS_COMPLETED | JOB_STATUS_FAILED | JOB_STATUS_CANCELLED
        )
    }
}

#[derive(Debug, Clone)]
struct TrackedJob {
    snapshot: ImportJobSnapshot,
    cancel_requested: bool,
    sequence: u64,
}

#[derive(Debug, Default)]
struct TrackerState {
    jobs: HashMap<String, TrackedJob>,
    next_sequence: u64,
}

/// `Arc`-backed thread-safe tracker for active and recent import jobs across agents.
#[derive(Debug, Clone)]
pub struct ImportJobTracker {
    inner: Arc<Mutex<TrackerState>>,
    max_terminal_per_agent: usize,
}

impl Default for ImportJobTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportJobTracker {
    pub fn new() -> Self {
        Self::with_retention(DEFAULT_MAX_TERMINAL_JOBS_PER_AGENT)
    }

    pub fn with_retention(max_terminal_per_agent: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerState::default())),
            max_terminal_per_agent: max_terminal_per_agent.max(1),
        }
    }

    /// Register a new running job with initial `(source_id, total_messages)` entries.
    pub fn start_job<I>(
        &self,
        job_id: impl Into<String>,
        agent_id: impl Into<String>,
        adapter_id: impl Into<String>,
        adapter_name: impl Into<String>,
        source_path: Option<String>,
        queued_conversations: I,
    ) -> ImportJobSnapshot
    where
        I: IntoIterator<Item = (String, usize)>,
    {
        let job_id = job_id.into();
        let agent_id = agent_id.into();
        let now = unix_now_ms();
        let mut conversation_states = BTreeMap::new();
        let mut total_messages = 0_usize;
        for (cid, msg_count) in queued_conversations {
            total_messages = total_messages.saturating_add(msg_count);
            conversation_states.insert(
                cid,
                ConversationProgressState {
                    status: CONV_STATUS_QUEUED.to_string(),
                    processed_messages: 0,
                    total_messages: msg_count,
                },
            );
        }
        let snapshot = ImportJobSnapshot {
            job_id: job_id.clone(),
            agent_id: agent_id.clone(),
            adapter_id: adapter_id.into(),
            adapter_name: adapter_name.into(),
            source_path,
            status: JOB_STATUS_RUNNING.to_string(),
            total_conversations: conversation_states.len(),
            completed_conversations: 0,
            skipped_conversations: 0,
            total_messages,
            processed_messages: 0,
            extracted_facts: 0,
            current_conversation_id: None,
            current_conversation_title: None,
            started_at_ms: now,
            updated_at_ms: now,
            error: None,
            conversation_states,
        };

        let mut guard = self.lock_state();
        guard.next_sequence = guard.next_sequence.wrapping_add(1);
        let seq = guard.next_sequence;
        guard.jobs.insert(
            job_id,
            TrackedJob {
                snapshot: snapshot.clone(),
                cancel_requested: false,
                sequence: seq,
            },
        );
        self.prune_agent_locked(&mut guard, &agent_id);
        snapshot
    }

    /// Convenience helper to start a job directly from scanned [`ConversationManifest`] items.
    pub fn start_job_from_manifests(
        &self,
        job_id: impl Into<String>,
        agent_id: impl Into<String>,
        adapter_id: impl Into<String>,
        adapter_name: impl Into<String>,
        source_path: Option<String>,
        manifests: &[ConversationManifest],
    ) -> ImportJobSnapshot {
        self.start_job(
            job_id,
            agent_id,
            adapter_id,
            adapter_name,
            source_path,
            manifests
                .iter()
                .map(|m| (m.source_id.clone(), m.message_count)),
        )
    }

    /// Mark `conversation_id` as actively `"importing"`.
    pub fn begin_conversation(
        &self,
        job_id: &str,
        conversation_id: &str,
        conversation_title: impl Into<String>,
        total_messages: usize,
    ) -> Option<ImportJobSnapshot> {
        let mut guard = self.lock_state();
        let tracked = guard.jobs.get_mut(job_id)?;
        let snap = &mut tracked.snapshot;
        snap.current_conversation_id = Some(conversation_id.to_string());
        snap.current_conversation_title = Some(conversation_title.into());
        match snap.conversation_states.get_mut(conversation_id) {
            Some(entry) => {
                if entry.total_messages == 0 && total_messages > 0 {
                    snap.total_messages = snap.total_messages.saturating_add(total_messages);
                    entry.total_messages = total_messages;
                }
                entry.status = CONV_STATUS_IMPORTING.to_string();
            }
            None => {
                snap.total_conversations = snap.total_conversations.saturating_add(1);
                snap.total_messages = snap.total_messages.saturating_add(total_messages);
                snap.conversation_states.insert(
                    conversation_id.to_string(),
                    ConversationProgressState {
                        status: CONV_STATUS_IMPORTING.to_string(),
                        processed_messages: 0,
                        total_messages,
                    },
                );
            }
        }
        snap.updated_at_ms = unix_now_ms();
        Some(snap.clone())
    }

    /// Increment processed message and extracted fact counters while importing a conversation.
    pub fn advance_messages(
        &self,
        job_id: &str,
        conversation_id: &str,
        delta_messages: usize,
        delta_facts: usize,
    ) -> Option<ImportJobSnapshot> {
        let mut guard = self.lock_state();
        let tracked = guard.jobs.get_mut(job_id)?;
        let snap = &mut tracked.snapshot;
        if let Some(entry) = snap.conversation_states.get_mut(conversation_id) {
            let prev = entry.processed_messages;
            let next = if entry.total_messages > 0 {
                prev.saturating_add(delta_messages)
                    .min(entry.total_messages)
            } else {
                prev.saturating_add(delta_messages)
            };
            entry.processed_messages = next;
            snap.processed_messages = snap.processed_messages.saturating_add(next - prev);
        } else {
            snap.processed_messages = snap.processed_messages.saturating_add(delta_messages);
        }
        snap.extracted_facts = snap.extracted_facts.saturating_add(delta_facts);
        snap.updated_at_ms = unix_now_ms();
        Some(snap.clone())
    }

    /// Finalize one conversation (`"done"`, `"skipped"`, or `"failed"`).
    pub fn finish_conversation(
        &self,
        job_id: &str,
        conversation_id: &str,
        status: &str,
        delta_facts: usize,
    ) -> Option<ImportJobSnapshot> {
        let mut guard = self.lock_state();
        let tracked = guard.jobs.get_mut(job_id)?;
        let snap = &mut tracked.snapshot;
        let normalized = match status.trim().to_ascii_lowercase().as_str() {
            CONV_STATUS_SKIPPED => CONV_STATUS_SKIPPED,
            CONV_STATUS_FAILED => CONV_STATUS_FAILED,
            _ => CONV_STATUS_DONE,
        };
        if let Some(entry) = snap.conversation_states.get_mut(conversation_id) {
            let was_done = entry.status == CONV_STATUS_DONE;
            let was_skipped = entry.status == CONV_STATUS_SKIPPED;
            if normalized == CONV_STATUS_DONE {
                if entry.processed_messages < entry.total_messages {
                    let rem = entry.total_messages - entry.processed_messages;
                    entry.processed_messages = entry.total_messages;
                    snap.processed_messages = snap.processed_messages.saturating_add(rem);
                }
                if !was_done {
                    snap.completed_conversations = snap.completed_conversations.saturating_add(1);
                }
            } else if normalized == CONV_STATUS_SKIPPED && !was_skipped {
                snap.skipped_conversations = snap.skipped_conversations.saturating_add(1);
            }
            entry.status = normalized.to_string();
        }
        snap.extracted_facts = snap.extracted_facts.saturating_add(delta_facts);
        if snap.current_conversation_id.as_deref() == Some(conversation_id) {
            snap.current_conversation_id = None;
            snap.current_conversation_title = None;
        }
        snap.updated_at_ms = unix_now_ms();
        Some(snap.clone())
    }

    /// Transition a job into its terminal state (`"completed"`, `"failed"`, or `"cancelled"`).
    pub fn finish_job(
        &self,
        job_id: &str,
        status: &str,
        error: Option<String>,
    ) -> Option<ImportJobSnapshot> {
        let mut guard = self.lock_state();
        let (agent_id, out) = {
            let tracked = guard.jobs.get_mut(job_id)?;
            let snap = &mut tracked.snapshot;
            let normalized = match status.trim().to_ascii_lowercase().as_str() {
                JOB_STATUS_FAILED => JOB_STATUS_FAILED,
                JOB_STATUS_CANCELLED => JOB_STATUS_CANCELLED,
                _ if tracked.cancel_requested => JOB_STATUS_CANCELLED,
                _ => JOB_STATUS_COMPLETED,
            };
            snap.status = normalized.to_string();
            snap.current_conversation_id = None;
            snap.current_conversation_title = None;
            snap.error = error;
            snap.updated_at_ms = unix_now_ms();
            (snap.agent_id.clone(), snap.clone())
        };
        self.prune_agent_locked(&mut guard, &agent_id);
        Some(out)
    }

    /// Request cooperative cancellation for a running job.
    pub fn request_cancel(&self, job_id: &str) -> bool {
        let mut guard = self.lock_state();
        let Some(tracked) = guard.jobs.get_mut(job_id) else {
            return false;
        };
        if tracked.snapshot.is_terminal() {
            return false;
        }
        tracked.cancel_requested = true;
        tracked.snapshot.updated_at_ms = unix_now_ms();
        true
    }

    /// Check whether cancellation has been requested (or completed) for `job_id`.
    pub fn is_cancelled(&self, job_id: &str) -> bool {
        let guard = self.lock_state();
        guard
            .jobs
            .get(job_id)
            .is_some_and(|t| t.cancel_requested || t.snapshot.status == JOB_STATUS_CANCELLED)
    }

    /// Retrieve a snapshot of `job_id`.
    pub fn get_job(&self, job_id: &str) -> Option<ImportJobSnapshot> {
        self.lock_state()
            .jobs
            .get(job_id)
            .map(|t| t.snapshot.clone())
    }

    /// List all active and retained recent jobs for `agent_id`, newest first.
    pub fn list_jobs_for_agent(&self, agent_id: &str) -> Vec<ImportJobSnapshot> {
        let guard = self.lock_state();
        let mut matched: Vec<&TrackedJob> = guard
            .jobs
            .values()
            .filter(|t| t.snapshot.agent_id == agent_id)
            .collect();
        matched.sort_by(|a, b| {
            b.snapshot
                .started_at_ms
                .cmp(&a.snapshot.started_at_ms)
                .then_with(|| b.sequence.cmp(&a.sequence))
        });
        matched.into_iter().map(|t| t.snapshot.clone()).collect()
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, TrackerState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn prune_agent_locked(&self, state: &mut TrackerState, agent_id: &str) {
        let mut terminal: Vec<(String, u64, u64)> = state
            .jobs
            .iter()
            .filter(|(_, t)| t.snapshot.agent_id == agent_id && t.snapshot.is_terminal())
            .map(|(id, t)| (id.clone(), t.snapshot.updated_at_ms, t.sequence))
            .collect();
        if terminal.len() <= self.max_terminal_per_agent {
            return;
        }
        terminal.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
        for (old_id, _, _) in terminal.into_iter().skip(self.max_terminal_per_agent) {
            state.jobs.remove(&old_id);
        }
    }
}
