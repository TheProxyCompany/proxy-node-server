//! Durable agent processes owned by the node, rather than by an HTTP client.
//!
//! The runtime owns its durable inbox and effect journal. This module owns its
//! process, authenticated attachment, and a replayable output log. A successful
//! pipe write is never reported as durable acceptance: only the runtime's
//! fsynced `accepted` event completes `submit`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};

pub mod handoff;
pub mod herdr;
mod host_control;
pub mod http;
pub mod pact;
pub mod pact_server;
mod party_children;
pub mod peer;
pub mod space;

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("invalid agent request: {0}")]
    Invalid(String),
    #[error("agent not registered: {0}")]
    NotFound(String),
    #[error("agent is busy; configuration was not changed")]
    Busy,
    #[error("agent access denied")]
    Forbidden,
    #[error("runtime acceptance is unknown; retry the same input id")]
    AcceptanceUnknown,
    #[error("runtime rejected input: {0}")]
    Rejected(String),
    #[error("agent process stopped")]
    Stopped,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Trusted application configuration. Never deserialize this from an HTTP
/// request or persist it: `env` can contain provider credentials.
#[derive(Clone, PartialEq)]
pub struct AgentSpec {
    pub id: String,
    pub display_name: Option<String>,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub agent_dir: PathBuf,
    pub state_dir: PathBuf,
    pub workspace: PathBuf,
    pub workspace_mode: WorkspaceMode,
    pub seat_config: Value,
    pub env: BTreeMap<String, String>,
    pub space: Option<SpaceBinding>,
}

/// Registration metadata for routing and authorization, without launch credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceDescriptor {
    pub id: String,
    pub creator_id: Option<String>,
    pub owner_agent_id: String,
    pub conversation_id: Option<String>,
    pub participant_id: Option<String>,
    pub task_id: Option<String>,
    pub agent_dir: PathBuf,
    pub state_dir: PathBuf,
    pub workspace: PathBuf,
    pub workspace_mode: WorkspaceMode,
}

// Media bindings are delivered through the live session. Updating them does not
// change the reasoning process, its context or its persistent shell.
fn same_runtime(left: &AgentSpec, right: &AgentSpec) -> bool {
    fn reasoning_roles(seat: &mut Value) {
        let thinking = seat["model_roles"]["thinking"].clone();
        if let Some(fields) = seat.as_object_mut() {
            fields.remove("model_roles");
            if !thinking.is_null() {
                fields.insert("model_roles".into(), json!({"thinking":thinking}));
            }
        }
    }
    fn reasoning_spec(spec: &AgentSpec) -> AgentSpec {
        let mut spec = spec.clone();
        reasoning_roles(&mut spec.seat_config);
        for key in ["PROXY_HARNESS_SEAT", "PROXY_AGENT_SEAT"] {
            if let Some(seat) = spec.env.get_mut(key) {
                if let Ok(mut value) = serde_json::from_str::<Value>(seat) {
                    reasoning_roles(&mut value);
                    *seat = value.to_string();
                }
            }
        }
        spec
    }
    reasoning_spec(left) == reasoning_spec(right)
}

/// Where shell, file and process tools execute. A host workspace is an
/// explicit authority choice, not an OS sandbox or a guest fallback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    #[default]
    Guest,
    Host,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceIsolation {
    Vm,
    Container,
    Shared,
}

/// Issued by the application's local Cua provisioner after checking the local
/// registry. This metadata cannot itself create isolation: the configured
/// native tools must execute in the provisioned guest, and CUA must target it.
/// Credentials belong only in `AgentSpec.env`, never in this value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceBinding {
    pub space_id: String,
    pub isolation: SpaceIsolation,
    pub workspace_root: PathBuf,
    pub endpoint: String,
}

impl SpaceBinding {
    fn validate(&self) -> Result<(), HostError> {
        if self.space_id.is_empty()
            || self.space_id.len() > 256
            || self.space_id.chars().any(char::is_control)
            || !self.workspace_root.is_absolute()
            || self.endpoint.is_empty()
            || self.endpoint.len() > 2048
        {
            return Err(HostError::Invalid(
                "invalid provisioned Cua Space binding".into(),
            ));
        }
        let endpoint = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| HostError::Invalid("invalid Cua endpoint".into()))?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.scheme(), "http" | "https" | "unix")
        {
            return Err(HostError::Invalid(
                "Cua endpoint cannot contain credentials or an unsupported transport".into(),
            ));
        }
        Ok(())
    }
}

/// Checked by the runtime after real inference and required tool/memory
/// initialization. Unknown or missing components never imply availability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeReadiness {
    pub ready: bool,
    pub agent_name: String,
    pub checked_at: u64,
    pub components: BTreeMap<String, ComponentReadiness>,
    #[serde(default)]
    pub work_ahead: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentReadiness {
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(flatten)]
    pub evidence: BTreeMap<String, Value>,
}
impl RuntimeReadiness {
    pub fn verified(&self) -> bool {
        let status = |key: &str, expected: &str| {
            self.components.get(key).is_some_and(|component| {
                component.ready && component.status.as_deref() == Some(expected)
            })
        };
        self.ready
            && self.checked_at > 0
            && !self.agent_name.trim().is_empty()
            && ["model", "mcp", "memory", "memory_adapters", "life_map"]
                .iter()
                .all(|key| {
                    self.components
                        .get(*key)
                        .is_some_and(|component| component.ready)
                })
            && status("model", "inference_verified")
            && status("mcp", "tools_verified")
            && status("memory", "journal_and_optchat_open")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentInput {
    pub id: String,
    #[serde(rename = "type", default = "prompt_kind")]
    pub kind: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

fn prompt_kind() -> String {
    "prompt".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostEvent {
    pub sequence: u64,
    pub agent_id: String,
    pub event: Value,
}

struct EventLog {
    file: File,
    sequence: u64,
    bytes: u64,
    offsets: BTreeMap<u64, u64>,
    input_starts: HashMap<String, u64>,
    deadline_at: Option<u64>,
    deadline_configured: bool,
    deadline_expired: bool,
    stop_reason: Option<String>,
    cleanup_confirmed: Option<bool>,
    retired: bool,
    admitted: bool,
    registered: bool,
    creator_id: Option<String>,
}

impl EventLog {
    fn deadline_passed(&self) -> bool {
        self.deadline_at.is_some_and(|at| {
            at <= std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        })
    }

    fn index(&mut self, record: &HostEvent, offset: u64) {
        if (record.sequence - 1) % 128 == 0 {
            self.offsets.insert(record.sequence, offset);
        }
        let event = &record.event;
        if event["type"] == "accepted" && event["durable"] == true {
            self.admitted = true;
        }
        if event["type"] == "host_instance_registered" {
            self.registered = true;
            self.creator_id = event["creator_id"].as_str().map(str::to_owned);
        }
        if event["type"] == "host_retired" {
            self.retired = true;
        } else if event["type"] == "host_deadline" {
            self.deadline_configured = true;
            self.deadline_at = event["deadline_at"].as_u64();
        } else if event["type"] == "host_deadline_expired" {
            self.deadline_expired = true;
            self.cleanup_confirmed = event["cleanup_confirmed"].as_bool();
            self.stop_reason = Some(
                if self.cleanup_confirmed == Some(true) {
                    "timed_out"
                } else {
                    "unknown"
                }
                .into(),
            );
        } else if event["type"] == "host_cancelled" {
            self.cleanup_confirmed = event["cleanup_confirmed"].as_bool();
            self.stop_reason = Some(
                if self.cleanup_confirmed == Some(true) {
                    "cancelled"
                } else {
                    "unknown"
                }
                .into(),
            );
        } else if event["type"] == "host_resumed" {
            self.stop_reason = None;
            self.cleanup_confirmed = None;
        }
        let input = event
            .get("event_id")
            .or_else(|| event.get("input_id"))
            .or_else(|| (event["type"] == "accepted").then(|| &event["id"]));
        if let Some(input) = input.and_then(Value::as_str) {
            self.input_starts
                .entry(input.into())
                .or_insert(record.sequence - 1);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShutdownMode {
    PreserveShell = 1,
    CancelInstance = 2,
}
impl ShutdownMode {
    fn confirmed(self, acknowledgement: u8) -> bool {
        acknowledgement == self as u8
            || (self == Self::PreserveShell && acknowledgement == Self::CancelInstance as u8)
    }
}

struct ProcessState {
    stop: Option<watch::Sender<Option<ShutdownMode>>>,
    finished: Option<oneshot::Receiver<()>>,
}

type Acknowledgements = HashMap<String, Vec<oneshot::Sender<Result<Value, String>>>>;

struct Agent {
    _lease: Arc<File>,
    creator: Option<String>,
    controls: Mutex<HashMap<String, party_children::Pending>>,
    host_controls: AtomicUsize,
    deadline: Mutex<Option<tokio::task::AbortHandle>>,
    spec: Mutex<AgentSpec>,
    process: AsyncMutex<ProcessState>,
    generation: AtomicU64,
    retired: AtomicBool,
    shutdown_confirmed: AtomicU8,
    restoration: Mutex<Option<Value>>,
    pid: AtomicU32,
    stdin: AsyncMutex<Option<ChildStdin>>,
    submission: AsyncMutex<()>,
    inputs: Mutex<HashSet<String>>,
    acknowledgements: Mutex<Acknowledgements>,
    state: Mutex<Value>,
    readiness: Mutex<Option<RuntimeReadiness>>,
    handoff: Mutex<Option<handoff::HandoffState>>,
    log: Mutex<EventLog>,
    log_path: PathBuf,
    updates: watch::Sender<u64>,
}

#[derive(Clone)]
pub struct AgentHost {
    root: PathBuf,
    agents: Arc<Mutex<HashMap<String, Arc<Agent>>>>,
    retired_ids: Arc<Mutex<HashSet<String>>>,
    lease: Arc<File>,
    closing: Arc<AtomicBool>,
    control_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
}

fn private_directory(path: &Path) -> Result<(), HostError> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_log(path: &Path, id: &str) -> Result<EventLog, HostError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    read_log(options.open(path)?, id, true)
}

fn read_log(file: File, id: &str, repair_incomplete_tail: bool) -> Result<EventLog, HostError> {
    let mut reader = BufReader::new(file.try_clone()?);
    let mut line = String::new();
    let mut log = EventLog {
        file,
        sequence: 0,
        bytes: 0,
        offsets: BTreeMap::new(),
        input_starts: HashMap::new(),
        deadline_at: None,
        deadline_configured: false,
        deadline_expired: false,
        stop_reason: None,
        cleanup_confirmed: None,
        retired: false,
        admitted: false,
        registered: false,
        creator_id: None,
    };
    let mut valid_end = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.ends_with('\n') {
            if repair_incomplete_tail {
                log.file.set_len(valid_end)?;
            }
            break;
        }
        let event: HostEvent = serde_json::from_str(&line)?;
        if event.sequence != log.sequence + 1 || event.agent_id != id {
            return Err(HostError::Invalid(
                "host event log sequence is corrupt".into(),
            ));
        }
        if event.event["type"] == "host_instance_registered"
            && log.registered
            && event.event["creator_id"].as_str() != log.creator_id.as_deref()
        {
            return Err(HostError::Invalid(
                "recorded instance creator changed".into(),
            ));
        }
        log.index(&event, valid_end);
        log.sequence = event.sequence;
        valid_end = reader.stream_position()?;
    }
    log.bytes = valid_end;
    Ok(log)
}

impl AgentHost {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, HostError> {
        private_directory(root.as_ref())?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lease = options.open(root.as_ref().join("host.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lease).map_err(|_| HostError::Busy)?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            agents: Arc::new(Mutex::new(HashMap::new())),
            retired_ids: Arc::new(Mutex::new(HashSet::new())),
            lease: Arc::new(lease),
            closing: Arc::new(AtomicBool::new(false)),
            control_tasks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Register a resolved loadout. Correlation belongs on each input, not the
    /// spec. A changed idle loadout stops its old process; a busy change fails
    /// explicitly instead of silently widening tools midway through a task.
    pub async fn register(&self, spec: AgentSpec) -> Result<(), HostError> {
        self.register_instance(spec, None).await
    }

    /// Every instance has its own process and address. A registered native creator
    /// can prepare its initial context, but the creator relationship requires no process.
    pub async fn register_spawned(
        &self,
        creator_id: &str,
        spec: AgentSpec,
    ) -> Result<(), HostError> {
        if !valid_id(creator_id) || creator_id == spec.id {
            return Err(HostError::Invalid(
                "a distinct creator id is required".into(),
            ));
        }
        if self.agent(&spec.id).is_err() {
            if let Ok(creator) = self.agent(creator_id) {
                party_children::validate_creator(&creator, &spec)?;
            }
        }
        self.register_instance(spec, Some(creator_id.into())).await
    }

    pub async fn register_party_child(
        &self,
        creator_id: &str,
        spec: AgentSpec,
    ) -> Result<(), HostError> {
        self.register_spawned(creator_id, spec).await
    }

    async fn register_instance(
        &self,
        spec: AgentSpec,
        creator: Option<String>,
    ) -> Result<(), HostError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(HostError::Stopped);
        }
        self.check_active_id(&spec.id)?;
        if let Some(space) = &spec.space {
            space.validate()?;
        }
        if spec.display_name.as_ref().is_some_and(|name| {
            name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control)
        }) {
            return Err(HostError::Invalid(
                "agent display name must be bounded and printable".into(),
            ));
        }
        if !valid_id(&spec.id)
            || !spec.command.is_absolute()
            || !spec.state_dir.is_absolute()
            || !spec.agent_dir.is_absolute()
            || !spec.workspace.is_absolute()
        {
            return Err(HostError::Invalid(
                "agent id and absolute configured paths are required".into(),
            ));
        }
        let existing = self.agents.lock().unwrap().get(&spec.id).cloned();
        if let Some(agent) = existing {
            if !party_children::same_creator(&agent, creator.as_deref()) {
                return Err(HostError::Invalid(
                    "an agent cannot change its recorded creator".into(),
                ));
            }
            let mut process = agent.process.lock().await;
            if self.closing.load(Ordering::SeqCst) {
                return Err(HostError::Stopped);
            }
            self.check_active_id(&spec.id)?;
            agent.check_active()?;
            if same_runtime(&agent.spec.lock().unwrap(), &spec) {
                *agent.spec.lock().unwrap() = spec;
                return Ok(());
            }
            if agent.has_pending_work()
                || !agent.controls.lock().unwrap().is_empty()
                || agent.host_controls.load(Ordering::SeqCst) != 0
            {
                return Err(HostError::Busy);
            }
            Self::stop_locked(&agent, &mut process, ShutdownMode::PreserveShell).await?;
            *agent.spec.lock().unwrap() = spec;
            *agent.restoration.lock().unwrap() = None;
            return Ok(());
        }
        let directory = self.root.join(&spec.id);
        private_directory(&directory)?;
        let log_path = directory.join("events.jsonl");
        let log = open_log(&log_path, &spec.id)?;
        if log.retired {
            return Err(HostError::Invalid(
                "agent handle is retired after migration".into(),
            ));
        }
        if log.registered && log.creator_id != creator {
            return Err(HostError::Invalid(
                "an agent cannot change its recorded creator".into(),
            ));
        }
        let state = json!({"status":log.stop_reason.as_deref().unwrap_or("stopped"),"cleanup_confirmed":log.cleanup_confirmed});
        let shutdown_confirmed = if log.cleanup_confirmed == Some(true) {
            ShutdownMode::CancelInstance as u8
        } else {
            0
        };
        let (updates, _) = watch::channel(log.sequence);
        let id = spec.id.clone();
        let agent = Arc::new(Agent {
            _lease: Arc::clone(&self.lease),
            creator,
            controls: Mutex::new(HashMap::new()),
            host_controls: AtomicUsize::new(0),
            deadline: Mutex::new(None),
            spec: Mutex::new(spec),
            process: AsyncMutex::new(ProcessState {
                stop: None,
                finished: None,
            }),
            generation: AtomicU64::new(0),
            retired: AtomicBool::new(false),
            shutdown_confirmed: AtomicU8::new(shutdown_confirmed),
            restoration: Mutex::new(None),
            pid: AtomicU32::new(0),
            stdin: AsyncMutex::new(None),
            submission: AsyncMutex::new(()),
            inputs: Mutex::new(HashSet::new()),
            acknowledgements: Mutex::new(HashMap::new()),
            state: Mutex::new(state),
            readiness: Mutex::new(None),
            handoff: Mutex::new(None),
            log: Mutex::new(log),
            log_path,
            updates,
        });
        // Concurrent identical registration converges on one process creator.
        let mut agents = self.agents.lock().unwrap();
        if self.closing.load(Ordering::SeqCst) {
            return Err(HostError::Stopped);
        }
        self.check_active_id(&id)?;
        if let Some(existing) = agents.get(&id) {
            existing.check_active()?;
            if !party_children::same_creator(existing, agent.creator.as_deref())
                || !same_runtime(&existing.spec.lock().unwrap(), &agent.spec.lock().unwrap())
            {
                return Err(HostError::Busy);
            }
        } else {
            publish(
                &agent,
                json!({"type":"host_instance_registered","instance_id":id,"creator_id":agent.creator}),
            )?;
            agents.insert(id, Arc::clone(&agent));
            host_control::resume_deadline(self, &agent);
        }
        Ok(())
    }

    fn check_active_id(&self, id: &str) -> Result<(), HostError> {
        if self.retired_ids.lock().unwrap().contains(id) {
            return Err(HostError::Invalid(
                "agent handle is retired after migration".into(),
            ));
        }
        Ok(())
    }

    fn agent(&self, id: &str) -> Result<Arc<Agent>, HostError> {
        self.agents
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| HostError::NotFound(id.into()))
    }

    pub fn registered_agents(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.agents.lock().unwrap().keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn descriptor(&self, id: &str) -> Result<InstanceDescriptor, HostError> {
        let agent = self.agent(id)?;
        let spec = agent.spec.lock().unwrap();
        let string = |key| spec.seat_config[key].as_str().map(str::to_owned);
        Ok(InstanceDescriptor {
            id: spec.id.clone(),
            creator_id: agent.creator.clone(),
            owner_agent_id: string("agent_id").unwrap_or_else(|| spec.id.clone()),
            conversation_id: string("conversation_id"),
            participant_id: string("participant_id"),
            task_id: string("task_id"),
            agent_dir: spec.agent_dir.clone(),
            state_dir: spec.state_dir.clone(),
            workspace: spec.workspace.clone(),
            workspace_mode: spec.workspace_mode,
        })
    }

    pub async fn ensure_started(&self, id: &str) -> Result<(), HostError> {
        self.check_active_id(id)?;
        let agent = self.agent(id)?;
        agent.check_active()?;
        if agent.is_restoring() {
            return Err(HostError::Busy);
        }
        if agent.process.lock().await.stop.is_some() {
            return Ok(());
        }
        if let Some(creator) = &agent.creator {
            let state = agent.spec.lock().unwrap().state_dir.clone();
            if !state.join("fork.json").is_file() && !state.join("log.jsonl").is_file() {
                if let Ok(parent) = self.agent(creator) {
                    self.ensure_instance_started(&parent).await?;
                    party_children::prepare(&agent, &parent).await?;
                }
            }
        }
        self.ensure_instance_started(&agent).await
    }

    async fn ensure_instance_started(&self, agent: &Arc<Agent>) -> Result<(), HostError> {
        let mut process = agent.process.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err(HostError::Stopped);
        }
        agent.check_active()?;
        if agent.is_restoring() {
            return Err(HostError::Busy);
        }
        if process.stop.is_some() {
            return Ok(());
        }
        let spec = agent.spec.lock().unwrap().clone();
        if agent.log.lock().unwrap().stop_reason.is_some() {
            publish(agent, json!({"type":"host_resumed"}))?;
        }
        *agent.readiness.lock().unwrap() = None;
        let child = spawn(&spec)?;
        let generation = agent.generation.fetch_add(1, Ordering::SeqCst) + 1;
        agent.mark_starting(child.id().unwrap_or(0));
        let (stop, stopped) = watch::channel(None);
        let (finished, completion) = oneshot::channel();
        process.stop = Some(stop);
        process.finished = Some(completion);
        tokio::spawn(supervise(
            self.clone(),
            Arc::clone(agent),
            child,
            stopped,
            generation,
            finished,
            None,
        ));
        Ok(())
    }

    /// Recover independently admitted descendants without reopening this creator's work.
    pub async fn restore_descendants(&self, id: &str) -> Result<Value, HostError> {
        self.check_active_id(id)?;
        if self.closing.load(Ordering::SeqCst) {
            return Err(HostError::Stopped);
        }
        let agent = self.agent(id)?;
        agent.check_active()?;
        let expire = {
            let log = agent.log.lock().unwrap();
            log.stop_reason.is_none() && log.deadline_passed()
        };
        if expire {
            if let Some(timer) = agent.deadline.lock().unwrap().take() {
                timer.abort();
            }
            let _ = host_control::cancel(self, id, true).await;
        }
        let mut process = agent.process.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err(HostError::Stopped);
        }
        agent.check_active()?;
        if agent.log.lock().unwrap().stop_reason.is_none() {
            return Err(HostError::Invalid(
                "restoration-only startup requires a stopped creator".into(),
            ));
        }
        if process.stop.is_some() {
            return Err(HostError::Busy);
        }
        if let Some(result) = agent.restoration.lock().unwrap().as_ref().filter(|value| {
            value["success"] == true && value["refused"].as_array().is_some_and(Vec::is_empty)
        }) {
            return Ok(result.clone());
        }
        let mut spec = agent.spec.lock().unwrap().clone();
        spec.args.push("--restore-instances-only".into());
        let child = spawn(&spec)?;
        *agent.restoration.lock().unwrap() = Some(json!({"status":"running"}));
        let generation = agent.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let (stop, stopped) = watch::channel(None);
        let (finished, completion) = oneshot::channel();
        let (result, restored) = oneshot::channel();
        process.stop = Some(stop);
        process.finished = Some(completion);
        tokio::spawn(supervise(
            self.clone(),
            Arc::clone(&agent),
            child,
            stopped,
            generation,
            finished,
            Some(result),
        ));
        drop(process);
        restored.await.map_err(|_| HostError::Stopped)?
    }

    pub async fn submit(&self, id: &str, input: AgentInput) -> Result<Value, HostError> {
        if input.id.is_empty()
            || input.id.len() > 256
            || !matches!(input.kind.as_str(), "prompt" | "event" | "observation")
            || input.message.len() > 4 * 1024 * 1024
        {
            return Err(HostError::Invalid(
                "stable input id, prompt/event/observation type and bounded message are required"
                    .into(),
            ));
        }
        let agent = self.agent(id)?;
        self.ensure_started(id).await?;
        let submission = agent.submission.lock().await;
        let (sender, response) = oneshot::channel();
        agent
            .acknowledgements
            .lock()
            .unwrap()
            .entry(input.id.clone())
            .or_default()
            .push(sender);
        let newly_pending = agent.inputs.lock().unwrap().insert(input.id.clone());
        let mut wire = serde_json::to_value(&input)?;
        // The logical identity is trusted registration data. A scoped task
        // runtime id is an implementation handle, not the agent identity.
        {
            let spec = agent.spec.lock().unwrap();
            wire["agent_id"] = spec
                .seat_config
                .get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or(&spec.id)
                .into();
        }
        if let Err(error) = agent.write(&wire).await {
            drop(response);
            let mut pending = agent.acknowledgements.lock().unwrap();
            if let Some(waiters) = pending.get_mut(&input.id) {
                waiters.retain(|waiter| !waiter.is_closed());
                if waiters.is_empty() {
                    pending.remove(&input.id);
                }
            }
            if newly_pending && matches!(error, HostError::Stopped) {
                agent.inputs.lock().unwrap().remove(&input.id);
            } else if matches!(error, HostError::Stopped) {
                return Err(HostError::AcceptanceUnknown);
            }
            return Err(error);
        }
        drop(submission);
        let result = match tokio::time::timeout(Duration::from_secs(30), response).await {
            Ok(Ok(Ok(ack))) => Ok(ack),
            Ok(Ok(Err(error))) => Err(HostError::Rejected(error)),
            _ => Err(HostError::AcceptanceUnknown),
        };
        // Drop timed-out/cancelled waiters rather than retain dead requests.
        let mut pending = agent.acknowledgements.lock().unwrap();
        if let Some(waiters) = pending.get_mut(&input.id) {
            waiters.retain(|waiter| !waiter.is_closed());
            if waiters.is_empty() {
                pending.remove(&input.id);
            }
        }
        result
    }

    /// Read prior admission and terminal state without registering or starting an instance.
    pub fn recorded_status(&self, id: &str) -> Result<Option<Value>, HostError> {
        if !valid_id(id) {
            return Err(HostError::Invalid("valid agent id is required".into()));
        }
        let file = match File::open(self.root.join(id).join("events.jsonl")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let log = read_log(file, id, false)?;
        let expired = log.deadline_expired || log.deadline_passed();
        Ok(Some(
            json!({"agent_id":id,"creator_id":log.creator_id,"admitted":log.admitted,"retired":log.retired,
            "deadline_at":log.deadline_at,"deadline_expired":expired,
            "runtime":{"status":log.stop_reason.as_deref().unwrap_or(if expired {"unknown"} else {"stopped"}),
                "cleanup_confirmed":log.cleanup_confirmed}}),
        ))
    }

    pub async fn status(&self, id: &str) -> Result<Value, HostError> {
        let agent = self.agent(id)?;
        let process = agent.process.lock().await;
        let pid = agent.pid.load(Ordering::SeqCst);
        let readiness = agent.readiness.lock().unwrap().clone();
        let workspace = {
            let spec = agent.spec.lock().unwrap();
            let root = match spec.workspace_mode {
                WorkspaceMode::Host => Some(spec.workspace.clone()),
                WorkspaceMode::Guest => spec
                    .space
                    .as_ref()
                    .map(|space| space.workspace_root.clone()),
            };
            json!({"mode":spec.workspace_mode,"root":root,"space_id":spec.space.as_ref().map(|space| &space.space_id),"os_sandbox":spec.workspace_mode == WorkspaceMode::Guest && spec.space.as_ref().is_some_and(|space| !matches!(&space.isolation, SpaceIsolation::Shared))})
        };
        let handoff = agent.handoff.lock().unwrap().clone();
        let retired = agent.retired.load(Ordering::SeqCst);
        let hosted = !retired && process.stop.is_some() && !agent.is_restoring();
        let available = handoff
            .as_ref()
            .is_none_or(|state| state.admission == "open")
            && pid != 0
            && hosted
            && readiness.as_ref().is_some_and(RuntimeReadiness::verified);
        Ok(
            json!({"agent_id":id,"pid":if pid==0 {None} else {Some(pid)},"hosted":hosted,"retired":retired,"creator_id":agent.creator,"address":format!("/client/agents/{id}"),
            "available":available,"readiness":readiness,"handoff":handoff,"workspace":workspace,
            "runtime":*agent.state.lock().unwrap(),"sequence":agent.log.lock().unwrap().sequence,
            "descriptor":self.descriptor(id)?}),
        )
    }

    pub fn subscribe(&self, id: &str, after_sequence: u64) -> Result<EventSubscription, HostError> {
        let agent = self.agent(id)?;
        let updates = agent.updates.subscribe();
        let log = agent.log.lock().unwrap();
        if after_sequence > log.sequence {
            return Err(HostError::Invalid(
                "event cursor is ahead of this agent".into(),
            ));
        }
        let mut reader = BufReader::new(File::open(&agent.log_path)?);
        if after_sequence == log.sequence {
            reader.seek(SeekFrom::End(0))?;
        } else if let Some((_, offset)) = log.offsets.range(..=after_sequence + 1).next_back() {
            reader.seek(SeekFrom::Start(*offset))?;
        }
        drop(log);
        Ok(EventSubscription {
            agent,
            updates,
            reader,
            after_sequence,
        })
    }

    /// Reattach at an input's first durable event, or at the current head when
    /// it has not appeared yet. The existing log rebuilds this index on open.
    pub fn input_cursor(&self, id: &str, input_id: &str) -> Result<u64, HostError> {
        if input_id.is_empty() || input_id.len() > 256 {
            return Err(HostError::Invalid("bounded input id is required".into()));
        }
        let agent = self.agent(id)?;
        let log = agent.log.lock().unwrap();
        Ok(log
            .input_starts
            .get(input_id)
            .copied()
            .unwrap_or(log.sequence))
    }

    pub async fn abort(&self, id: &str) -> Result<(), HostError> {
        let agent = self.agent(id)?;
        agent.check_active()?;
        if agent.is_restoring() {
            return Err(HostError::Busy);
        }
        let mut pipe = agent.stdin.lock().await;
        let pipe = pipe.as_mut().ok_or(HostError::Stopped)?;
        pipe.write_all(b"{\"type\":\"abort\"}\n").await?;
        pipe.flush().await?;
        Ok(())
    }

    /// Stop this owned process without discarding its accepted inbox or journal.
    /// A host-placement change uses this before transferring durable state.
    pub async fn stop(&self, id: &str) -> Result<(), HostError> {
        let agent = self.agent(id)?;
        let mut process = agent.process.lock().await;
        Self::stop_locked(&agent, &mut process, ShutdownMode::PreserveShell).await
    }

    /// Terminal cancellation requires an acknowledgement that includes idle shell cleanup.
    pub async fn cancel_instance(&self, id: &str) -> Result<(), HostError> {
        let agent = self.agent(id)?;
        let mut process = agent.process.lock().await;
        Self::stop_locked(&agent, &mut process, ShutdownMode::CancelInstance).await
    }

    async fn stop_locked(
        agent: &Arc<Agent>,
        process: &mut ProcessState,
        mode: ShutdownMode,
    ) -> Result<(), HostError> {
        let running = process.stop.is_some() && agent.pid.load(Ordering::SeqCst) != 0;
        agent.generation.fetch_add(1, Ordering::SeqCst);
        agent.controls.lock().unwrap().clear();
        if let Some(stop) = process.stop.take() {
            let _ = stop.send(Some(mode));
        }
        if let Some(finished) = process.finished.take() {
            let _ = finished.await;
        }
        agent.pid.store(0, Ordering::SeqCst);
        *agent.stdin.lock().await = None;
        *agent.readiness.lock().unwrap() = None;
        {
            let log = agent.log.lock().unwrap();
            *agent.state.lock().unwrap() = json!({"status":log.stop_reason.as_deref().unwrap_or("stopped"),
                "cleanup_confirmed":log.cleanup_confirmed,"pending":agent.inputs.lock().unwrap().len()});
        }
        if (running || mode == ShutdownMode::CancelInstance)
            && !mode.confirmed(agent.shutdown_confirmed.load(Ordering::SeqCst))
        {
            return Err(HostError::Rejected(
                "runtime stopped without confirming shell cleanup; work outcome is unknown".into(),
            ));
        }
        Ok(())
    }

    /// Permanently fence a migrated handle in this host while retaining its
    /// journal and subscriptions. The caller verifies durable handoff or
    /// exclusive offline ownership first. An unknown id is tombstoned without
    /// creating any registration, state directory, or process.
    pub async fn retire(&self, id: &str) -> Result<(), HostError> {
        if !valid_id(id) {
            return Err(HostError::Invalid("valid agent id is required".into()));
        }
        self.retired_ids.lock().unwrap().insert(id.into());
        let agent = self.agents.lock().unwrap().get(id).cloned();
        if let Some(agent) = agent {
            let mut process = agent.process.lock().await;
            agent.retired.store(true, Ordering::SeqCst);
            Self::stop_locked(&agent, &mut process, ShutdownMode::PreserveShell).await?;
            publish(&agent, json!({"type":"host_retired"}))?;
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        let controls: Vec<_> = self.control_tasks.lock().unwrap().drain(..).collect();
        for task in &controls {
            task.abort();
        }
        for task in controls {
            let _ = task.await;
        }
        let agents: Vec<_> = self.agents.lock().unwrap().values().cloned().collect();
        for agent in agents {
            if let Some(deadline) = agent.deadline.lock().unwrap().take() {
                deadline.abort();
            }
            let mut process = agent.process.lock().await;
            agent.generation.fetch_add(1, Ordering::SeqCst);
            agent.controls.lock().unwrap().clear();
            if let Some(stop) = process.stop.take() {
                let _ = stop.send(Some(ShutdownMode::PreserveShell));
            }
            if let Some(finished) = process.finished.take() {
                let _ = finished.await;
            }
        }
    }
}

/// A disk-backed cursor, not a lossy broadcast queue. Slow/disconnected clients
/// can resume after a node restart without keeping their backlog in RAM.
pub struct EventSubscription {
    agent: Arc<Agent>,
    updates: watch::Receiver<u64>,
    reader: BufReader<File>,
    after_sequence: u64,
}

impl EventSubscription {
    pub async fn recv(&mut self) -> Result<HostEvent, HostError> {
        loop {
            {
                let _log = self.agent.log.lock().unwrap();
                let mut line = String::new();
                while self.reader.read_line(&mut line)? != 0 {
                    let event: HostEvent = serde_json::from_str(&line)?;
                    line.clear();
                    if event.sequence > self.after_sequence {
                        self.after_sequence = event.sequence;
                        return Ok(event);
                    }
                }
            }
            self.updates
                .changed()
                .await
                .map_err(|_| HostError::Stopped)?;
        }
    }

    pub async fn next(&mut self) -> Result<HostEvent, HostError> {
        self.recv().await
    }
}

impl Agent {
    fn is_restoring(&self) -> bool {
        self.restoration
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|value| value["status"] == "running")
    }

    fn mark_starting(&self, pid: u32) {
        *self.restoration.lock().unwrap() = None;
        self.shutdown_confirmed.store(0, Ordering::SeqCst);
        *self.state.lock().unwrap() = json!({"status":"starting"});
        self.pid.store(pid, Ordering::SeqCst);
    }

    /// The durable runtime can recover admitted work without a new Node submit.
    /// Its state receipt therefore also fences configuration changes. A live
    /// process that has not reported its initial state is still starting.
    fn has_pending_work(&self) -> bool {
        if self.is_restoring() {
            return true;
        }
        if !self.inputs.lock().unwrap().is_empty() {
            return true;
        }
        let state = self.state.lock().unwrap();
        matches!(
            state["status"].as_str(),
            Some("running" | "starting" | "recovering")
        ) || state["input_id"].as_str().is_some()
            || state["pending"].as_u64().is_some_and(|count| count > 0)
            || state["queue_depth"].as_u64().is_some_and(|count| count > 0)
            || (self.pid.load(Ordering::SeqCst) != 0
                && !matches!(state["status"].as_str(), Some("idle" | "paused")))
    }

    fn check_active(&self) -> Result<(), HostError> {
        if self.retired.load(Ordering::SeqCst) {
            return Err(HostError::Invalid(
                "agent handle is retired after migration".into(),
            ));
        }
        Ok(())
    }

    /// The process belongs to this object, never to the attached client.
    async fn write(&self, wire: &Value) -> Result<(), HostError> {
        self.check_active()?;
        if self.is_restoring() {
            return Err(HostError::Busy);
        }
        self.write_direct(wire).await
    }

    async fn write_direct(&self, wire: &Value) -> Result<(), HostError> {
        self.check_active()?;
        use tokio::io::AsyncWriteExt;
        let bytes = format!("{wire}\n").into_bytes();
        let mut written = 0;
        match tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut stdin = self.stdin.lock().await;
                if self.retired.load(Ordering::SeqCst) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "agent handle is retired",
                    ));
                }
                if let Some(stdin) = stdin.as_mut() {
                    while written < bytes.len() {
                        let count = stdin.write(&bytes[written..]).await?;
                        if count == 0 {
                            return Err(std::io::ErrorKind::WriteZero.into());
                        }
                        written += count;
                    }
                    stdin.flush().await?;
                    return Ok::<_, std::io::Error>(());
                }
                drop(stdin);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            _ if written == 0 => Err(HostError::Stopped),
            _ => Err(HostError::AcceptanceUnknown),
        }
    }
}

/// Persistent launch specs from an older host remain valid; canonical entries win.
fn canonical_harness_environment(
    environment: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut canonical = BTreeMap::new();
    for (name, value) in environment {
        if let Some(suffix) = name.strip_prefix("PROXY_AGENT_") {
            canonical.insert(format!("PROXY_HARNESS_{suffix}"), value.clone());
        }
    }
    canonical.extend(
        environment
            .iter()
            .filter(|(name, _)| !name.starts_with("PROXY_AGENT_"))
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    canonical
}

fn scrub_harness_environment(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| {
            name.starts_with("PROXY_HARNESS_") || name.starts_with("PROXY_AGENT_")
        }) {
            command.env_remove(name);
        }
    }
}

fn spawn(spec: &AgentSpec) -> Result<Child, HostError> {
    let mut seat_config = spec.seat_config.clone();
    seat_config["workspace_mode"] = serde_json::to_value(spec.workspace_mode)?;
    let mut command = Command::new(&spec.command);
    let directory = if spec.workspace_mode == WorkspaceMode::Guest && !spec.workspace.is_dir() {
        &spec.state_dir
    } else {
        &spec.workspace
    };
    scrub_harness_environment(&mut command);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command
            .as_std_mut()
            .arg0(spec.display_name.as_deref().unwrap_or(&spec.id));
    }
    command
        .args(&spec.args)
        .args(["--rpc", "--agent"])
        .arg(&spec.agent_dir)
        .arg("--state")
        .arg(&spec.state_dir)
        .arg("--workspace")
        .arg(&spec.workspace)
        .current_dir(directory)
        .envs(canonical_harness_environment(&spec.env))
        .env(
            "PROXY_HARNESS_HOSTED",
            if spec
                .env
                .get("PROXY_HARNESS_HOST_CONTROL")
                .is_some_and(|capability| capability == "1")
            {
                "1"
            } else {
                "0"
            },
        )
        .env("PROXY_HARNESS_INSTANCE_ID", &spec.id)
        .env("PROXY_HARNESS_SEAT", serde_json::to_string(&seat_config)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(space) = &spec.space {
        command.env("PROXY_HARNESS_SPACE", serde_json::to_string(space)?);
    } else {
        command.env_remove("PROXY_HARNESS_SPACE");
    }
    let fork = spec.state_dir.join("fork.json");
    if fork.is_file() {
        command.env("PROXY_HARNESS_FORK", fork);
    }
    Ok(command.spawn()?)
}

fn publish(agent: &Agent, event: Value) -> Result<(), HostError> {
    if party_children::route(agent, &event)? {
        return Ok(());
    }
    let mut log = agent.log.lock().unwrap();
    let record = HostEvent {
        sequence: log.sequence + 1,
        agent_id: agent.spec.lock().unwrap().id.clone(),
        event: event.clone(),
    };
    let bytes = serde_json::to_vec(&record)?;
    log.file.write_all(&bytes)?;
    log.file.write_all(b"\n")?;
    let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
    if kind == "response" && event["command"] == "shutdown" {
        let mode = if event["cancel_instance"] == true {
            ShutdownMode::CancelInstance
        } else {
            ShutdownMode::PreserveShell
        };
        agent.shutdown_confirmed.store(
            if event["success"] == true {
                mode as u8
            } else {
                0
            },
            Ordering::SeqCst,
        );
    }
    if matches!(
        kind,
        "accepted"
            | "agent_settled"
            | "observation_recorded"
            | "root_readiness"
            | "host_process_exit"
            | "host_party_child_started"
            | "host_retired"
            | "host_error"
            | "host_deadline"
            | "host_deadline_expired"
            | "host_cancelled"
            | "host_resumed"
            | "host_restoration_complete"
    ) || kind == "handoff_state"
        || (kind == "response" && handoff::is_command(&event))
    {
        log.file.sync_data()?;
    }
    let offset = log.bytes;
    log.index(&record, offset);
    log.bytes += bytes.len() as u64 + 1;
    log.sequence = record.sequence;
    // The agent is idle before anyone hears that it settled: a subscriber
    // that reacts to agent_settled may change its configuration at once.
    if matches!(kind, "agent_settled" | "observation_recorded") {
        if let Some(id) = event
            .get("event_id")
            .or_else(|| event.get("id"))
            .and_then(Value::as_str)
        {
            let mut inputs = agent.inputs.lock().unwrap();
            inputs.remove(id);
            if inputs.is_empty() {
                let mut state = agent.state.lock().unwrap();
                if state["input_id"].as_str() == Some(id) || state["input_id"].is_null() {
                    state["status"] = json!("idle");
                    state["input_id"] = Value::Null;
                }
            }
        }
    }
    agent.updates.send_replace(record.sequence);
    drop(log);
    if kind == "root_state" {
        *agent.state.lock().unwrap() = event.clone();
    } else if kind == "root_readiness" {
        *agent.readiness.lock().unwrap() = serde_json::from_value(event.clone()).ok();
    } else if matches!(kind, "host_process_exit" | "host_error") {
        *agent.readiness.lock().unwrap() = None;
        if kind == "host_process_exit" && event["stopping"] != true {
            // No new runtime state is known during restart backoff. Retain
            // recovered work as an ownership fence until the next state receipt.
            agent.state.lock().unwrap()["status"] = json!("recovering");
        }
    } else if matches!(kind, "host_deadline_expired" | "host_cancelled") {
        let mut state = agent.state.lock().unwrap();
        state["cleanup_confirmed"] = event["cleanup_confirmed"].clone();
        state["status"] = if event["cleanup_confirmed"] != true {
            json!("unknown")
        } else if kind == "host_deadline_expired" {
            json!("timed_out")
        } else {
            json!("cancelled")
        };
    }
    let handoff_reply = kind == "response"
        && handoff::is_command(&event)
        && event.get("success") == Some(&Value::Bool(true));
    if kind == "handoff_state" || handoff_reply {
        if let Some(data) = event.get("data") {
            if let Ok(state) = serde_json::from_value(data.clone()) {
                *agent.handoff.lock().unwrap() = Some(state);
            }
        }
    }
    let id = if kind == "response" {
        event.get("id").or_else(|| event.get("event_id"))
    } else {
        event.get("event_id").or_else(|| event.get("id"))
    }
    .and_then(Value::as_str);
    if let Some(id) = id {
        if (kind == "accepted" && event.get("durable") == Some(&Value::Bool(true))) || handoff_reply
        {
            if let Some(waiters) = agent.acknowledgements.lock().unwrap().remove(id) {
                for waiter in waiters {
                    let _ = waiter.send(Ok(event.clone()));
                }
            }
        } else if kind == "response" && event.get("success") == Some(&Value::Bool(false)) {
            agent.inputs.lock().unwrap().remove(id);
            if let Some(waiters) = agent.acknowledgements.lock().unwrap().remove(id) {
                let error = event
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("runtime refused input");
                for waiter in waiters {
                    let _ = waiter.send(Err(error.into()));
                }
            }
        }
    }
    Ok(())
}

async fn supervise(
    host: AgentHost,
    agent: Arc<Agent>,
    mut child: Child,
    mut stop: watch::Receiver<Option<ShutdownMode>>,
    generation: u64,
    finished: oneshot::Sender<()>,
    restoration: Option<oneshot::Sender<Result<Value, HostError>>>,
) {
    let mut failures = 0u32;
    let restoring = restoration.is_some();
    let mut restoration_result = Err(HostError::Rejected(
        "runtime did not confirm descendant restoration".into(),
    ));
    let herdr = if restoring {
        None
    } else {
        let spec = agent.spec.lock().unwrap();
        herdr::HerdrBridge::from_environment(&spec.env, &spec.id)
            .map(|bridge| Arc::new(bridge).start())
    };
    loop {
        *agent.stdin.lock().await = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let output_agent = Arc::clone(&agent);
        let output_host = host.clone();
        let reporter = herdr.clone();
        let output = tokio::spawn(async move {
            let mut restored = None;
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let event = serde_json::from_str(&line).unwrap_or_else(
                    |_| json!({"type":"host_error","error":"runtime emitted invalid JSON"}),
                );
                if host_control::route(&output_host, &output_agent, generation, &event) {
                    continue;
                }
                if restoring {
                    if event["type"] == "host_restoration_complete" && event["success"] == true {
                        restored = Some(event);
                    } else {
                        restored = None;
                        break;
                    }
                    continue;
                }
                if let (Some(reporter), Some(state)) = (&reporter, herdr::state_for(&event)) {
                    reporter.send_replace(Some(state));
                }
                if publish(&output_agent, event).is_err() {
                    break;
                }
            }
            restored
        });
        // Drain stderr so a diagnostic cannot deadlock the process. It is not
        // persisted: provider errors may include secrets or request bodies.
        let errors = tokio::spawn(async move {
            let mut stderr = stderr;
            let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        });
        let status = tokio::select! {
            result = child.wait() => result,
            _ = tokio::time::sleep(Duration::from_secs(100)), if restoring => {
                let _ = child.kill().await;
                child.wait().await
            }
            _ = stop.changed() => {
                // Explicit host stop gives the runtime its own scoped cleanup path.
                // A process crash or a lost client never sends this command.
                let _ = tokio::time::timeout(Duration::from_secs(1), async {
                    let mut stdin = agent.stdin.lock().await;
                    if let Some(stdin) = stdin.as_mut() {
                        let cancel = *stop.borrow() == Some(ShutdownMode::CancelInstance);
                        let command = format!("{}\n", json!({"type":"shutdown","cancel_instance":cancel}));
                        stdin.write_all(command.as_bytes()).await?;
                        stdin.flush().await?;
                    }
                    Ok::<_, std::io::Error>(())
                }).await;
                match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                    Ok(status) => status,
                    Err(_) => { let _ = child.kill().await; child.wait().await }
                }
            }
        };
        let restored = output.await.ok().flatten();
        let _ = errors.await;
        if restoring {
            *agent.stdin.lock().await = None;
            if status.as_ref().is_ok_and(|status| status.success()) && stop.borrow().is_none() {
                if let Some(result) = restored {
                    restoration_result = publish(&agent, result.clone()).map(|_| result);
                }
            }
            break;
        }
        if stop
            .borrow()
            .is_some_and(|mode| !mode.confirmed(agent.shutdown_confirmed.load(Ordering::SeqCst)))
        {
            let _ = publish(
                &agent,
                json!({"type":"host_error","error":"runtime stopped without confirming shell cleanup; work outcome is unknown"}),
            );
        }
        *agent.stdin.lock().await = None;
        agent.pid.store(0, Ordering::SeqCst);
        agent.controls.lock().unwrap().clear();
        let _ = publish(
            &agent,
            json!({"type":"host_process_exit","code":status.ok().and_then(|s|s.code()),"stopping":stop.borrow().is_some()}),
        );
        if stop.borrow().is_some() {
            break;
        }
        failures += 1;
        if failures >= 5 {
            let _ = publish(
                &agent,
                json!({"type":"host_error","error":"runtime repeatedly exited; explicit retry required"}),
            );
            break;
        }
        tokio::select! {
            _ = stop.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(250u64 << failures)) => {}
        }
        let spec = agent.spec.lock().unwrap().clone();
        match spawn(&spec) {
            Ok(next) => {
                child = next;
                if agent.generation.load(Ordering::SeqCst) != generation {
                    let _ = child.kill().await;
                    break;
                }
                agent.mark_starting(child.id().unwrap_or(0));
            }
            Err(_) => {
                let _ = publish(
                    &agent,
                    json!({"type":"host_error","error":"runtime restart failed"}),
                );
                break;
            }
        }
    }
    if let Some(reporter) = herdr {
        reporter.send_replace(None);
    }
    if agent.generation.load(Ordering::SeqCst) == generation {
        agent.pid.store(0, Ordering::SeqCst);
    }
    // Signal before the lifecycle lock: reconfiguration holds that lock while
    // awaiting the old process's death, so it cannot race a new pipe into it.
    let _ = finished.send(());
    let mut process = agent.process.lock().await;
    if agent.generation.load(Ordering::SeqCst) == generation {
        process.stop = None;
    }
    if let Some(restored) = restoration {
        *agent.restoration.lock().unwrap() = restoration_result.as_ref().ok().cloned();
        let _ = restored.send(restoration_result);
    }
}

#[cfg(test)]
mod handoff_wire_tests {
    use super::*;

    #[tokio::test]
    async fn durable_event_replay_seeks_near_its_cursor() {
        let root = tempfile::tempdir().unwrap();
        let host = AgentHost::open(root.path()).unwrap();
        host.register(AgentSpec {
            id: "indexed".into(),
            display_name: None,
            command: root.path().join("unused"),
            args: vec![],
            agent_dir: root.path().join("identity"),
            state_dir: root.path().join("state"),
            workspace: root.path().into(),
            workspace_mode: WorkspaceMode::Host,
            seat_config: json!({}),
            env: BTreeMap::new(),
            space: None,
        })
        .await
        .unwrap();
        let agent = host.agent("indexed").unwrap();
        for index in 0..1024 {
            publish(
                &agent,
                json!({"type":"message_update", "event_id":format!("input-{index}")}),
            )
            .unwrap();
        }
        let cursor = host.input_cursor("indexed", "input-1000").unwrap();
        let mut subscription = host.subscribe("indexed", cursor).unwrap();
        let seek = subscription.reader.stream_position().unwrap();
        assert!(
            seek > agent.log.lock().unwrap().bytes / 2,
            "must seek past old history"
        );
        let event = subscription.recv().await.unwrap();
        assert_eq!(event.sequence, cursor + 1);
        assert_eq!(event.event["event_id"], "input-1000");
    }

    #[tokio::test]
    async fn recovered_runtime_work_prevents_configuration_replacement() {
        let root = tempfile::tempdir().unwrap();
        let host = AgentHost::open(root.path().join("host")).unwrap();
        let spec = AgentSpec {
            id: "recovered".into(),
            display_name: None,
            command: "/bin/sh".into(),
            args: vec![],
            agent_dir: root.path().join("definition"),
            state_dir: root.path().join("state"),
            workspace: root.path().into(),
            workspace_mode: WorkspaceMode::Host,
            seat_config: json!({"model":"original"}),
            env: BTreeMap::new(),
            space: None,
        };
        host.register(spec.clone()).await.unwrap();
        let agent = host.agent("recovered").unwrap();
        assert!(agent.inputs.lock().unwrap().is_empty());
        let mut changed = spec.clone();
        changed.seat_config["model"] = json!("replacement");
        for state in [
            json!({"type":"root_state","status":"running","input_id":"recovered-input","queue_depth":0}),
            json!({"type":"root_state","status":"idle","input_id":null,"queue_depth":2}),
        ] {
            publish(&agent, state).unwrap();
            assert!(matches!(
                host.register(changed.clone()).await,
                Err(HostError::Busy)
            ));
            assert_eq!(agent.spec.lock().unwrap().seat_config["model"], "original");
            host.register(spec.clone()).await.unwrap();
        }
        publish(
            &agent,
            json!({"type":"root_state","status":"idle","input_id":null,"queue_depth":0}),
        )
        .unwrap();
        host.register(changed).await.unwrap();
        assert_eq!(
            agent.spec.lock().unwrap().seat_config["model"],
            "replacement"
        );
        // Stale idle state must not survive either explicit start or automatic restart.
        agent.mark_starting(42);
        assert!(matches!(
            host.register(spec.clone()).await,
            Err(HostError::Busy)
        ));
        agent.pid.store(0, Ordering::SeqCst);
        publish(
            &agent,
            json!({"type":"root_state","status":"idle","input_id":null,"queue_depth":0}),
        )
        .unwrap();
        publish(
            &agent,
            json!({"type":"host_process_exit","stopping":false,"code":1}),
        )
        .unwrap();
        assert!(matches!(
            host.register(spec.clone()).await,
            Err(HostError::Busy)
        ));

        // A child's recovered queue does not prevent its creator from reconfiguring.
        publish(
            &agent,
            json!({"type":"root_state","status":"idle","input_id":null,"queue_depth":0}),
        )
        .unwrap();
        let mut child_spec = spec.clone();
        child_spec.id = "recovered-child".into();
        child_spec.state_dir = root.path().join("child-state");
        host.register_party_child("recovered", child_spec)
            .await
            .unwrap();
        let child = host.agent("recovered-child").unwrap();
        assert!(child.inputs.lock().unwrap().is_empty());
        publish(&child,json!({"type":"root_state","status":"running","input_id":"child-recovered","queue_depth":0})).unwrap();
        host.register(spec.clone()).await.unwrap();
        publish(
            &child,
            json!({"type":"root_state","status":"idle","input_id":null,"queue_depth":0}),
        )
        .unwrap();
        host.register(spec).await.unwrap();
    }

    #[test]
    fn saved_environment_migrates_once_and_canonical_authority_wins() {
        let canonical = canonical_harness_environment(&BTreeMap::from([
            ("PROXY_AGENT_API_KEY".into(), "old".into()),
            ("PROXY_HARNESS_API_KEY".into(), "new".into()),
            ("PROXY_AGENT_SEAT".into(), "old-seat".into()),
            ("PATH".into(), "/bin".into()),
        ]));
        assert_eq!(canonical.get("PROXY_HARNESS_API_KEY").unwrap(), "new");
        assert_eq!(canonical.get("PROXY_HARNESS_SEAT").unwrap(), "old-seat");
        assert_eq!(canonical.get("PATH").unwrap(), "/bin");
        assert!(!canonical.keys().any(|key| key.starts_with("PROXY_AGENT_")));
    }

    #[tokio::test]
    async fn asynchronous_native_handoff_data_updates_availability_and_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let host = AgentHost::open(root.path().join("host")).unwrap();
        host.register(AgentSpec {
            id: "dot".into(),
            display_name: None,
            command: root.path().join("fixture"),
            args: vec![],
            agent_dir: root.path().join("definition"),
            state_dir: root.path().join("state"),
            workspace: root.path().into(),
            workspace_mode: WorkspaceMode::Host,
            seat_config: json!({}),
            env: BTreeMap::new(),
            space: None,
        })
        .await
        .unwrap();
        let agent = host.agent("dot").unwrap();
        let checkpoint = json!({"handoff_id":"move-dot","admission":"paused","ready":true,
            "durable":true,"assessment_pending":false,"reason":null,"active_input":null,"accepted_pending":0,"active_processes":0,
            "unknown_effects":0,"cursors":{"inbox":{"bytes":0,"sha256":"a".repeat(64)},
            "journal":{"bytes":10,"sha256":"b".repeat(64),"sequence":1,"journal_id":"dot-journal"}}});
        publish(&agent, json!({"type":"handoff_state","data":checkpoint})).unwrap();
        let status = host.status("dot").await.unwrap();
        assert_eq!(status["handoff"], checkpoint);
        assert!(!status["available"].as_bool().unwrap());
        assert!(agent.handoff.lock().unwrap().as_ref().unwrap().verified());
        let mut events = host.subscribe("dot", 0).unwrap();
        assert_eq!(
            events.recv().await.unwrap().event["type"],
            "host_instance_registered"
        );
        assert_eq!(events.recv().await.unwrap().event["data"], checkpoint);
    }
}
