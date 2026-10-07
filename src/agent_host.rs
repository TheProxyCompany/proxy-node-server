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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};

pub mod handoff;
pub mod herdr;
pub mod http;
pub mod pact;
pub mod pact_server;
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
}

struct ProcessState {
    stop: Option<watch::Sender<bool>>,
    finished: Option<oneshot::Receiver<()>>,
}

type Acknowledgements = HashMap<String, Vec<oneshot::Sender<Result<Value, String>>>>;

struct Agent {
    _lease: Arc<File>,
    spec: Mutex<AgentSpec>,
    process: AsyncMutex<ProcessState>,
    generation: AtomicU64,
    pid: AtomicU32,
    stdin: AsyncMutex<Option<ChildStdin>>,
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
    lease: Arc<File>,
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

fn open_log(path: &Path) -> Result<EventLog, HostError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let mut reader = BufReader::new(file.try_clone()?);
    let mut line = String::new();
    let mut sequence = 0;
    let mut valid_end = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.ends_with('\n') {
            file.set_len(valid_end)?;
            break;
        }
        let event: HostEvent = serde_json::from_str(&line)?;
        if event.sequence != sequence + 1 {
            return Err(HostError::Invalid(
                "host event log sequence is corrupt".into(),
            ));
        }
        sequence = event.sequence;
        valid_end = reader.stream_position()?;
    }
    Ok(EventLog { file, sequence })
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
            lease: Arc::new(lease),
        })
    }

    /// Register a resolved loadout. Correlation belongs on each input, not the
    /// spec. A changed idle loadout stops its old process; a busy change fails
    /// explicitly instead of silently widening tools midway through a task.
    pub async fn register(&self, spec: AgentSpec) -> Result<(), HostError> {
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
            let mut process = agent.process.lock().await;
            if *agent.spec.lock().unwrap() == spec {
                return Ok(());
            }
            if !agent.inputs.lock().unwrap().is_empty() {
                return Err(HostError::Busy);
            }
            agent.generation.fetch_add(1, Ordering::SeqCst);
            if let Some(stop) = process.stop.take() {
                let _ = stop.send(true);
            }
            if let Some(finished) = process.finished.take() {
                let _ = finished.await;
            }
            agent.pid.store(0, Ordering::SeqCst);
            *agent.stdin.lock().await = None;
            *agent.readiness.lock().unwrap() = None;
            *agent.spec.lock().unwrap() = spec;
            return Ok(());
        }
        let directory = self.root.join(&spec.id);
        private_directory(&directory)?;
        let log_path = directory.join("events.jsonl");
        let log = open_log(&log_path)?;
        let (updates, _) = watch::channel(log.sequence);
        let id = spec.id.clone();
        let agent = Arc::new(Agent {
            _lease: Arc::clone(&self.lease),
            spec: Mutex::new(spec),
            process: AsyncMutex::new(ProcessState {
                stop: None,
                finished: None,
            }),
            generation: AtomicU64::new(0),
            pid: AtomicU32::new(0),
            stdin: AsyncMutex::new(None),
            inputs: Mutex::new(HashSet::new()),
            acknowledgements: Mutex::new(HashMap::new()),
            state: Mutex::new(json!({"status":"stopped"})),
            readiness: Mutex::new(None),
            handoff: Mutex::new(None),
            log: Mutex::new(log),
            log_path,
            updates,
        });
        // Concurrent identical registration converges on one process owner.
        let mut agents = self.agents.lock().unwrap();
        if let Some(existing) = agents.get(&id) {
            if *existing.spec.lock().unwrap() != *agent.spec.lock().unwrap() {
                return Err(HostError::Busy);
            }
        } else {
            agents.insert(id, agent);
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

    pub async fn ensure_started(&self, id: &str) -> Result<(), HostError> {
        let agent = self.agent(id)?;
        let mut process = agent.process.lock().await;
        if process.stop.is_some() {
            return Ok(());
        }
        let spec = agent.spec.lock().unwrap().clone();
        *agent.readiness.lock().unwrap() = None;
        let child = spawn(&spec)?;
        let generation = agent.generation.fetch_add(1, Ordering::SeqCst) + 1;
        agent.pid.store(child.id().unwrap_or(0), Ordering::SeqCst);
        let (stop, stopped) = watch::channel(false);
        let (finished, completion) = oneshot::channel();
        process.stop = Some(stop);
        process.finished = Some(completion);
        tokio::spawn(supervise(
            Arc::clone(&agent),
            child,
            stopped,
            generation,
            finished,
        ));
        Ok(())
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
        let (sender, response) = oneshot::channel();
        agent
            .acknowledgements
            .lock()
            .unwrap()
            .entry(input.id.clone())
            .or_default()
            .push(sender);
        agent.inputs.lock().unwrap().insert(input.id.clone());
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
        if agent.write(&wire).await.is_err() {
            agent.acknowledgements.lock().unwrap().remove(&input.id);
            return Err(HostError::AcceptanceUnknown);
        }
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
        let available = handoff
            .as_ref()
            .is_none_or(|state| state.admission == "open")
            && pid != 0
            && process.stop.is_some()
            && readiness.as_ref().is_some_and(RuntimeReadiness::verified);
        Ok(
            json!({"agent_id":id,"pid":if pid==0 {None} else {Some(pid)},"hosted":process.stop.is_some(),
            "available":available,"readiness":readiness,"handoff":handoff,"workspace":workspace,
            "runtime":*agent.state.lock().unwrap(),"sequence":agent.log.lock().unwrap().sequence}),
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
        }
        drop(log);
        Ok(EventSubscription {
            agent,
            updates,
            reader,
            after_sequence,
        })
    }

    pub async fn abort(&self, id: &str) -> Result<(), HostError> {
        let agent = self.agent(id)?;
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
        agent.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(stop) = process.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(finished) = process.finished.take() {
            let _ = finished.await;
        }
        agent.pid.store(0, Ordering::SeqCst);
        *agent.stdin.lock().await = None;
        *agent.readiness.lock().unwrap() = None;
        *agent.state.lock().unwrap() =
            json!({"status":"stopped","pending":agent.inputs.lock().unwrap().len()});
        Ok(())
    }

    pub async fn shutdown(&self) {
        let agents: Vec<_> = self.agents.lock().unwrap().values().cloned().collect();
        for agent in agents {
            let mut process = agent.process.lock().await;
            if let Some(stop) = process.stop.take() {
                let _ = stop.send(true);
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
    /// The process belongs to this object, never to the attached client.
    async fn write(&self, wire: &Value) -> Result<(), HostError> {
        use tokio::io::AsyncWriteExt;
        match tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut stdin = self.stdin.lock().await;
                if let Some(stdin) = stdin.as_mut() {
                    stdin.write_all(format!("{wire}\n").as_bytes()).await?;
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
            _ => Err(HostError::AcceptanceUnknown),
        }
    }
}

fn spawn(spec: &AgentSpec) -> Result<Child, HostError> {
    let mut seat_config = spec.seat_config.clone();
    seat_config["workspace_mode"] = serde_json::to_value(spec.workspace_mode)?;
    let mut command = Command::new(&spec.command);
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
        .current_dir(&spec.workspace)
        .envs(&spec.env)
        .env("PROXY_AGENT_SEAT", serde_json::to_string(&seat_config)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(space) = &spec.space {
        command.env("PROXY_AGENT_SPACE", serde_json::to_string(space)?);
    } else {
        command.env_remove("PROXY_AGENT_SPACE");
    }
    Ok(command.spawn()?)
}

fn publish(agent: &Agent, event: Value) -> Result<(), HostError> {
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
    if matches!(
        kind,
        "accepted"
            | "agent_settled"
            | "observation_recorded"
            | "root_readiness"
            | "host_process_exit"
            | "host_error"
    ) || kind == "handoff_state"
        || (kind == "response" && handoff::is_command(&event))
    {
        log.file.sync_data()?;
    }
    log.sequence = record.sequence;
    agent.updates.send_replace(record.sequence);
    drop(log);
    if kind == "root_state" {
        *agent.state.lock().unwrap() = event.clone();
    } else if kind == "root_readiness" {
        *agent.readiness.lock().unwrap() = serde_json::from_value(event.clone()).ok();
    } else if matches!(kind, "host_process_exit" | "host_error") {
        *agent.readiness.lock().unwrap() = None;
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
        } else if matches!(kind, "agent_settled" | "observation_recorded") {
            agent.inputs.lock().unwrap().remove(id);
        }
    }
    Ok(())
}

async fn supervise(
    agent: Arc<Agent>,
    mut child: Child,
    mut stop: watch::Receiver<bool>,
    generation: u64,
    finished: oneshot::Sender<()>,
) {
    let mut failures = 0u32;
    let herdr = {
        let spec = agent.spec.lock().unwrap();
        herdr::HerdrBridge::from_environment(&spec.env, &spec.id)
            .map(|bridge| Arc::new(bridge).start())
    };
    loop {
        *agent.stdin.lock().await = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let output_agent = Arc::clone(&agent);
        let reporter = herdr.clone();
        let output = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let event = serde_json::from_str(&line).unwrap_or_else(
                    |_| json!({"type":"host_error","error":"runtime emitted invalid JSON"}),
                );
                if let (Some(reporter), Some(state)) = (&reporter, herdr::state_for(&event)) {
                    reporter.send_replace(Some(state));
                }
                if publish(&output_agent, event).is_err() {
                    break;
                }
            }
        });
        // Drain stderr so a diagnostic cannot deadlock the process. It is not
        // persisted: provider errors may include secrets or request bodies.
        let errors = tokio::spawn(async move {
            let mut stderr = stderr;
            let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        });
        let status = tokio::select! {
            result = child.wait() => result,
            _ = stop.changed() => { let _ = child.kill().await; child.wait().await }
        };
        let _ = output.await;
        let _ = errors.await;
        *agent.stdin.lock().await = None;
        let _ = publish(
            &agent,
            json!({"type":"host_process_exit","code":status.ok().and_then(|s|s.code()),"stopping":*stop.borrow()}),
        );
        if *stop.borrow() {
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
                agent.pid.store(child.id().unwrap_or(0), Ordering::SeqCst);
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
}

#[cfg(test)]
mod handoff_wire_tests {
    use super::*;

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
        assert_eq!(events.recv().await.unwrap().event["data"], checkpoint);
    }
}
