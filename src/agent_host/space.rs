//! Local Cua provisioning. Ownership is recorded before creation so an
//! interrupted request never adopts another user's desktop. Versioned
//! reservations can retry an initial create on a healthy backend; established
//! guests are never replaced when they are missing after runtime recovery.
//! Cua CLI/core SDK are MIT; the separately installed spacesd is FSL-1.1-MIT.
//! This module calls the installed service and does not vendor its source.

#[path = "space_home.rs"]
mod home;
#[path = "space_managed.rs"]
mod managed;

// Migration identity: retain the existing lock, receipts and resource names.
// Renaming these would allow old and new hosts to own the same logical agent.
const LEGACY_OWNERS_DIRECTORY: &str = "proxy-agent-owners";
const LEGACY_SPACE_PREFIX: &str = "proxy-agent-";

use super::{HostError, SpaceBinding, SpaceIsolation, private_directory, valid_id};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSpaceKind {
    LinuxContainer,
    MacosVm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceResources {
    pub kind: LocalSpaceKind,
    pub cpus: u16,
    pub memory_mb: u32,
    /// VM disk target; containers must use zero (their engine owns storage).
    pub disk_gb: u32,
}
impl Default for SpaceResources {
    fn default() -> Self {
        Self {
            kind: LocalSpaceKind::LinuxContainer,
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 0,
        }
    }
}

/// Trusted launch data, issued by this provisioner, never accepted from MCP
/// callers. It contains local paths, not Cua credentials. The CLI keeps those
/// in its own private store. A caller MUST still pin the sandbox on every call:
/// the CLI's --sandbox option alone is only a default, not an access boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CuaMcpLaunch {
    pub space_id: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionedSpace {
    pub binding: SpaceBinding,
    pub mcp: CuaMcpLaunch,
}

pub struct StoppedSpace {
    runtime: String,
    namespace: String,
    space_id: String,
    provisioned: bool,
}

impl StoppedSpace {
    pub(super) fn owns_child(&self, creator: &super::AgentSpec, child: &str) -> bool {
        self.runtime == CuaSpaceManager::child_runtime(&creator.id, child)
            && creator.space.as_ref().is_some_and(|parent| {
                parent.space_id
                    == format!(
                        "local:{}",
                        CuaSpaceManager::name(&self.namespace, &creator.id)
                    )
            })
            && self.space_id
                == format!(
                    "local:{}",
                    CuaSpaceManager::name(&self.namespace, &self.runtime)
                )
    }

    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    pub fn was_provisioned(&self) -> bool {
        self.provisioned
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CreationState {
    Reserved,
    Established,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Ownership {
    version: u32,
    agent_id: String,
    name: String,
    resources: SpaceResources,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creation: Option<CreationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<SpaceBinding>,
}
impl Ownership {
    fn reserved(&self) -> bool {
        self.version == 2 && self.creation == Some(CreationState::Reserved)
    }
}

#[derive(Clone)]
pub struct CuaSpaceManager {
    binary: PathBuf,
    root: PathBuf,
    home: PathBuf,
    namespace: String,
    _lease: Arc<File>,
    mutation: Arc<Mutex<()>>,
}

impl CuaSpaceManager {
    pub fn child_runtime(parent: &str, child: &str) -> String {
        let hash = Sha256::digest(format!("{parent}\0{child}").as_bytes());
        format!(
            "child-{}",
            hash.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }
    /// Use a Proxy-owned data directory, never the user's global ~/.cua.
    /// No cloud account, relay registration, or host desktop is selected.
    pub fn open(binary: impl AsRef<Path>, root: impl AsRef<Path>) -> Result<Self, HostError> {
        let binary = binary.as_ref();
        let root = root.as_ref();
        if !binary.is_absolute() || !binary.is_file() || !root.is_absolute() {
            return Err(HostError::Invalid(
                "Cua requires an installed absolute binary and private data root".into(),
            ));
        }
        private_directory(root)?;
        private_directory(&root.join(LEGACY_OWNERS_DIRECTORY))?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lease = options.open(root.join(LEGACY_OWNERS_DIRECTORY).join("manager.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lease).map_err(|_| HostError::Busy)?;
        let (home, namespace) = home::open(root)?;
        Ok(Self {
            binary: binary.into(),
            home,
            namespace,
            root: root.into(),
            _lease: Arc::new(lease),
            mutation: Arc::new(Mutex::new(())),
        })
    }

    fn name(namespace: &str, agent: &str) -> String {
        let hash = Sha256::digest(format!("{namespace}\0{agent}").as_bytes());
        format!(
            "{LEGACY_SPACE_PREFIX}{}",
            hash[..12]
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        )
    }
    fn receipt(&self, agent: &str) -> PathBuf {
        self.root
            .join(LEGACY_OWNERS_DIRECTORY)
            .join(format!("{}.json", Self::name(&self.namespace, agent)))
    }

    pub fn deferred_binding(
        &self,
        agent: &str,
        resources: &SpaceResources,
    ) -> Result<SpaceBinding, HostError> {
        if !valid_id(agent) {
            return Err(HostError::Invalid("valid agent id is required".into()));
        }
        Ok(SpaceBinding {
            space_id: format!("local:{}", Self::name(&self.namespace, agent)),
            isolation: match resources.kind {
                LocalSpaceKind::LinuxContainer => SpaceIsolation::Container,
                LocalSpaceKind::MacosVm => SpaceIsolation::Vm,
            },
            workspace_root: None,
            endpoint: None,
        })
    }

    /// Read preparation state without creating, starting, or executing in a guest.
    pub fn space_status(&self, agent: &str, declared: &SpaceBinding) -> Result<Value, HostError> {
        match self.load_owner(agent) {
            Ok(owner) => {
                let binding = owner.binding.as_ref().unwrap_or(declared);
                binding.validate()?;
                if binding.space_id != format!("local:{}", owner.name)
                    || !matches!(
                        (&owner.resources.kind, &binding.isolation),
                        (LocalSpaceKind::LinuxContainer, SpaceIsolation::Container)
                            | (LocalSpaceKind::MacosVm, SpaceIsolation::Vm)
                    )
                {
                    return Err(HostError::Invalid(
                        "recorded guest binding does not match its owner".into(),
                    ));
                }
                let resource_state = if binding.workspace_root.is_some() {
                    "prepared"
                } else if owner.reserved() {
                    "reserved"
                } else {
                    "unknown"
                };
                Ok(serde_json::json!({
                    "space": binding,"provisioned":true,"resource_state":resource_state,
                }))
            }
            Err(HostError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(
                serde_json::json!({"space":declared,"provisioned":false,"resource_state":"absent"}),
            ),
            Err(error) => Err(error),
        }
    }
    fn load_owner(&self, agent: &str) -> Result<Ownership, HostError> {
        let owner: Ownership = serde_json::from_slice(&std::fs::read(self.receipt(agent))?)?;
        if !matches!(owner.version, 1 | 2)
            || (owner.version == 2 && owner.creation.is_none())
            || owner.agent_id != agent
            || owner.name != Self::name(&self.namespace, agent)
        {
            return Err(HostError::Invalid(
                "Cua Space ownership record does not match agent".into(),
            ));
        }
        Ok(owner)
    }

    /// Read retained metadata without booting, starting, executing, or creating a guest.
    pub fn recorded_binding(
        &self,
        agent: &str,
        state: &Path,
    ) -> Result<Option<SpaceBinding>, HostError> {
        use std::io::{BufRead, BufReader};
        if !valid_id(agent) {
            return Err(HostError::Invalid("valid agent id is required".into()));
        }
        let file = match File::open(state.join("inbox.jsonl")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut authority = None;
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 || !line.ends_with('\n') {
                break;
            }
            let record: Value = serde_json::from_str(&line)?;
            if record["kind"] == "input" && record["input"]["_authority"].is_object() {
                authority = Some(record["input"]["_authority"].clone());
            }
        }
        let Some(authority) = authority.filter(|value| !value["space"].is_null()) else {
            return Ok(None);
        };
        let binding: SpaceBinding = serde_json::from_value(authority["space"].clone())?;
        binding.validate()?;
        if binding.space_id != format!("local:{}", Self::name(&self.namespace, agent)) {
            return Err(HostError::Invalid(
                "recorded guest binding does not match its owner".into(),
            ));
        }
        let Some(endpoint) = &binding.endpoint else {
            // Keep the original admission immutable after a deferred guest is
            // prepared. Its current path is available through space_status.
            return Ok(Some(binding));
        };
        let owner = self.load_owner(agent)?;
        let endpoint = reqwest::Url::parse(endpoint)
            .map_err(|_| HostError::Invalid("invalid recorded guest endpoint".into()))?;
        if binding.space_id != format!("local:{}", owner.name)
            || !matches!(
                endpoint.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
            )
            || !matches!(
                (&owner.resources.kind, &binding.isolation),
                (LocalSpaceKind::LinuxContainer, SpaceIsolation::Container)
                    | (LocalSpaceKind::MacosVm, SpaceIsolation::Vm)
            )
        {
            return Err(HostError::Invalid(
                "recorded guest binding does not match its owner".into(),
            ));
        }
        Ok(Some(binding))
    }

    fn establish(
        &self,
        agent: &str,
        owner: &Ownership,
        binding: &SpaceBinding,
    ) -> Result<(), HostError> {
        if !owner.reserved() && owner.binding.as_ref() == Some(binding) {
            return Ok(());
        }
        if self.load_owner(agent)? != *owner {
            return Err(HostError::Busy);
        }
        let receipt = self.receipt(agent);
        let mut updated = owner.clone();
        if updated.version == 2 {
            updated.creation = Some(CreationState::Established);
        }
        updated.binding = Some(binding.clone());
        use rand_core::RngCore;
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = receipt.with_extension(format!("establishing-{nonce}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            use std::io::Write;
            let mut file = options.open(&temporary)?;
            file.write_all(&serde_json::to_vec(&updated)?)?;
            file.sync_all()?;
            if self.load_owner(agent)? != *owner {
                return Err(HostError::Busy);
            }
            std::fs::rename(&temporary, &receipt)?;
            File::open(receipt.parent().expect("receipt has parent"))?.sync_all()?;
            Ok(())
        })();
        let _ = std::fs::remove_file(temporary);
        result
    }
    fn base_args(&self) -> Vec<String> {
        vec![
            "--embedded".into(),
            "--state-dir".into(),
            self.root.join("sandboxes").to_string_lossy().into_owned(),
            "--json".into(),
        ]
    }
    fn env(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("CUA_HOME".into(), self.home.to_string_lossy().into_owned()),
            ("CUA_TELEMETRY".into(), "0".into()),
            ("DO_NOT_TRACK".into(), "1".into()),
        ])
    }
    async fn run(&self, args: &[String], timeout: Duration) -> Result<Vec<u8>, HostError> {
        let mut cmd = Command::new(&self.binary);
        cmd.args(self.base_args())
            .args(args)
            .envs(self.env())
            .env_remove("CUA_DAEMON")
            .env_remove("CUA_DAEMON_TOKEN")
            .env_remove("CUA_SANDBOX")
            .env_remove("CUA_MCP_PERMISSIONS")
            .stdin(Stdio::null());
        let operation = format!(
            "local Cua {}",
            args.iter().take(2).cloned().collect::<Vec<_>>().join(" ")
        );
        run_command(cmd, timeout, &operation).await
    }
    async fn json(&self, args: &[String]) -> Result<Value, HostError> {
        Ok(serde_json::from_slice(
            &self.run(args, Duration::from_secs(60)).await?,
        )?)
    }
    async fn listed(&self, name: &str) -> Result<bool, HostError> {
        let list = self
            .json(&[
                "sb".into(),
                "ls".into(),
                "--local".into(),
                "--no-size".into(),
            ])
            .await?;
        let entries = list
            .as_array()
            .ok_or_else(|| HostError::Invalid("Cua returned an invalid local registry".into()))?;
        Ok(entries.iter().any(|v| v["name"].as_str() == Some(name)))
    }

    pub async fn ensure_agent_space(
        &self,
        agent: &str,
        resources: SpaceResources,
    ) -> Result<ProvisionedSpace, HostError> {
        if !valid_id(agent)
            || resources.cpus == 0
            || resources.cpus > 64
            || resources.memory_mb < 1024
            || resources.memory_mb > 262144
            || match resources.kind {
                LocalSpaceKind::LinuxContainer => resources.disk_gb != 0,
                LocalSpaceKind::MacosVm => resources.disk_gb < 8 || resources.disk_gb > 1024,
            }
        {
            return Err(HostError::Invalid(
                "invalid local Space agent or resource limits".into(),
            ));
        }
        let _guard = self.mutation.lock().await;
        let _shared = home::lock(&self.home).await?;
        let name = Self::name(&self.namespace, agent);
        let receipt = self.receipt(agent);
        let mut owner = if receipt.try_exists()? {
            Some(self.load_owner(agent)?)
        } else {
            None
        };
        if let Some(owner) = &owner {
            if owner.resources != resources {
                return Err(HostError::Invalid(
                    "Space resources changed; stop and explicitly migrate the existing guest"
                        .into(),
                ));
            }
            if resources.kind == LocalSpaceKind::LinuxContainer {
                // Cua 0.4.1 checks a guest's status before booting its engine.
                // After an unclean host shutdown this reports "missing" even
                // though the guest's disk is intact in the stopped managed VM.
                managed::ensure_existing(self).await?;
            }
        }
        let mut exists = self.listed(&name).await?;
        if let Some(owner) = &owner {
            if !exists {
                if !owner.reserved() {
                    return Err(HostError::Invalid(
                        "The owned Cua guest is missing after runtime recovery; its ownership and files were preserved. Explicit recovery is required".into(),
                    ));
                }
                let report = self.json(&["runtime".into(), "doctor".into()]).await?;
                if !managed::backend_healthy(&self.home, &resources.kind, &report).await? {
                    return Err(HostError::Invalid("Initial Cua provisioning remains reserved because its backend is not healthy enough to confirm absence; retry after runtime recovery".into()));
                }
                // Re-inspect after confirming engine health. A successful
                // earlier create may have returned before its receipt advanced.
                exists = self.listed(&name).await?;
            }
        }
        if owner.is_none() {
            if exists {
                return Err(HostError::Forbidden);
            }
            let reservation = Ownership {
                version: 2,
                agent_id: agent.into(),
                name: name.clone(),
                resources: resources.clone(),
                creation: Some(CreationState::Reserved),
                binding: None,
            };
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&receipt)?;
            use std::io::Write;
            file.write_all(&serde_json::to_vec(&reservation)?)?;
            file.sync_all()?;
            File::open(receipt.parent().expect("receipt has parent"))?.sync_all()?;
            owner = Some(reservation);
        }
        let id = format!("local:{name}");
        if !exists {
            let (image, kind, runtime) = match resources.kind {
                LocalSpaceKind::LinuxContainer => ("linux", "container", "runc"),
                LocalSpaceKind::MacosVm => ("macos:26", "vm", "lume"),
            };
            let mut args = [
                "spaces",
                "create",
                image,
                "--on",
                "local",
                "--kind",
                kind,
                "--runtime",
                runtime,
                "--name",
                &name,
                "--cpus",
                &resources.cpus.to_string(),
                "--memory-mb",
                &resources.memory_mb.to_string(),
            ]
            .map(String::from)
            .to_vec();
            if resources.kind == LocalSpaceKind::MacosVm {
                args.extend(["--disk-gb".into(), resources.disk_gb.to_string()]);
            }
            self.run(&args, Duration::from_secs(900)).await?;
        } else {
            let info = self.json(&["sb".into(), "info".into(), id.clone()]).await?;
            if info["state"] != "running" {
                self.run(
                    &["spaces".into(), "start".into(), id.clone()],
                    Duration::from_secs(300),
                )
                .await?;
            }
        }
        let info = self.json(&["sb".into(), "info".into(), id.clone()]).await?;
        let isolation = match resources.kind {
            LocalSpaceKind::LinuxContainer => SpaceIsolation::Container,
            LocalSpaceKind::MacosVm => SpaceIsolation::Vm,
        };
        let expected_kind = match isolation {
            SpaceIsolation::Container => "container",
            SpaceIsolation::Vm => "vm",
            SpaceIsolation::Shared => unreachable!(),
        };
        if info["id"] != id
            || info["location"] != "local"
            || info["kind"] != expected_kind
            || info["state"] != "running"
            || info["status"] != "ready"
        {
            return Err(HostError::Invalid(
                "Cua guest is not ready with the requested local isolation".into(),
            ));
        }
        let endpoint = info["endpoints"]["env"]
            .as_str()
            .ok_or_else(|| HostError::Invalid("Cua guest has no spacesd endpoint".into()))?
            .to_string();
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|_| HostError::Invalid("invalid local guest endpoint".into()))?;
        if !matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        ) {
            return Err(HostError::Invalid(
                "local Cua guest must expose a loopback endpoint".into(),
            ));
        }
        // Persist the workspace in this guest's own home, never /tmp or a host mount.
        let home = self
            .json(&[
                "sb".into(),
                "exec".into(),
                id.clone(),
                "printenv HOME".into(),
            ])
            .await?;
        let home = home["stdout"].as_str().unwrap_or_default().trim();
        if !Path::new(home).is_absolute() || home.chars().any(char::is_control) {
            return Err(HostError::Invalid(
                "Cua guest did not provide an absolute home directory".into(),
            ));
        }
        let workspace_root = Path::new(home).join("ProxyWorkspace");
        let quoted = format!(
            "'{}'",
            workspace_root.to_string_lossy().replace('\'', "'\"'\"'")
        );
        self.run(
            &[
                "sb".into(),
                "exec".into(),
                id.clone(),
                format!("mkdir -p {quoted} && chmod 700 {quoted}"),
            ],
            Duration::from_secs(60),
        )
        .await?;
        let binding = SpaceBinding {
            space_id: id.clone(),
            isolation,
            workspace_root: Some(workspace_root),
            endpoint: Some(endpoint),
        };
        binding.validate()?;
        // Publish the actual binding only after this guest and workspace are ready.
        self.establish(
            agent,
            owner.as_ref().expect("ownership was recorded"),
            &binding,
        )?;
        let mut args = self.base_args();
        args.extend([
            "mcp".into(),
            "--permissions".into(),
            "computer:all".into(),
            "--sandbox".into(),
            id.clone(),
        ]);
        Ok(ProvisionedSpace {
            binding,
            mcp: CuaMcpLaunch {
                space_id: id,
                command: self.binary.clone(),
                args,
                env: self.env(),
            },
        })
    }

    /// Stop only a previously provisioned guest. Ownership is retained so a
    /// later request resumes its files. There is deliberately no implicit delete.
    pub async fn stop_agent_space(&self, agent: &str) -> Result<StoppedSpace, HostError> {
        let _guard = self.mutation.lock().await;
        let _shared = home::lock(&self.home).await?;
        let owner = match self.load_owner(agent) {
            Ok(owner) => owner,
            Err(HostError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoppedSpace {
                    runtime: agent.into(),
                    namespace: self.namespace.clone(),
                    space_id: format!("local:{}", Self::name(&self.namespace, agent)),
                    provisioned: false,
                });
            }
            Err(error) => return Err(error),
        };
        if owner.reserved() && owner.binding.is_none() && !self.listed(&owner.name).await? {
            let report = self.json(&["runtime".into(), "doctor".into()]).await?;
            if !managed::backend_healthy(&self.home, &owner.resources.kind, &report).await? {
                return Err(HostError::Invalid(
                    "Cua could not confirm the reserved guest is absent; its lease was retained"
                        .into(),
                ));
            }
            if !self.listed(&owner.name).await? {
                return Ok(StoppedSpace {
                    runtime: agent.into(),
                    namespace: self.namespace.clone(),
                    space_id: format!("local:{}", owner.name),
                    provisioned: false,
                });
            }
        }
        self.run(
            &[
                "spaces".into(),
                "stop".into(),
                format!("local:{}", owner.name),
            ],
            Duration::from_secs(120),
        )
        .await?;
        let info = self
            .json(&["sb".into(), "info".into(), format!("local:{}", owner.name)])
            .await?;
        if info["id"] != format!("local:{}", owner.name)
            || !matches!(
                info["state"].as_str(),
                Some("stopped" | "suspended" | "paused")
            )
        {
            return Err(HostError::Invalid(
                "Cua did not confirm the owned guest stopped; its lease was retained".into(),
            ));
        }
        Ok(StoppedSpace {
            runtime: agent.into(),
            namespace: self.namespace.clone(),
            space_id: format!("local:{}", owner.name),
            provisioned: true,
        })
    }
}

/// Cua can exit successfully with a structured failed setup step. Preserve its
/// bounded diagnostic instead of reducing every failure to a generic message.
async fn run_command(
    mut command: Command,
    timeout: Duration,
    operation: &str,
) -> Result<Vec<u8>, HostError> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or(HostError::Stopped)?;
    let stderr = child.stderr.take().ok_or(HostError::Stopped)?;
    let result = tokio::time::timeout(timeout, async {
        tokio::try_join!(
            bounded_output(stdout, 4 * 1024 * 1024),
            bounded_output(stderr, 64 * 1024),
            child.wait()
        )
    })
    .await;
    let (stdout, stderr, status) = match result {
        Ok(Ok(output)) => output,
        failed => {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            let detail = match failed {
                Ok(Err(error)) => error.to_string(),
                Err(_) => "timed out; inspect before retrying".into(),
                Ok(Ok(_)) => unreachable!(),
            };
            return Err(HostError::Invalid(format!("{operation}: {detail}")));
        }
    };
    if !status.success() {
        let message = String::from_utf8_lossy(&stderr);
        let stderr_detail = message
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(diagnostic);
        let stdout_detail = serde_json::from_slice::<Value>(&stdout)
            .ok()
            .and_then(|value| structured_failure(&value))
            .map(|error| diagnostic(&error));
        let detail = match (stdout_detail, stderr_detail) {
            (Some(error), Some(stderr)) if error != stderr => format!("{error}; stderr: {stderr}"),
            (Some(error), _) => error,
            (_, Some(stderr)) => stderr,
            _ => "no diagnostic returned".into(),
        };
        return Err(HostError::Invalid(format!(
            "{operation} failed ({status}): {detail}"
        )));
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&stdout) {
        if let Some(error) = structured_failure(&value) {
            return Err(HostError::Invalid(format!(
                "{operation}: {}",
                diagnostic(&error)
            )));
        }
    }
    Ok(stdout)
}

async fn bounded_output(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(std::io::Error::other(
            "Cua command output exceeded its bounded limit",
        ));
    }
    Ok(bytes)
}

fn diagnostic(message: &str) -> String {
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect()
}

fn structured_failure(value: &Value) -> Option<String> {
    if let Some(steps) = value.as_array() {
        return steps.iter().find_map(structured_failure);
    }
    // Cua 0.4.1 wraps `spaces create --json` results, including failed rows.
    if let Some(spaces) = value.get("spaces").and_then(Value::as_array)
        && let Some(error) = spaces.iter().find_map(structured_failure)
    {
        return Some(error);
    }
    let failed = value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| {
            status.eq_ignore_ascii_case("error") || status.eq_ignore_ascii_case("failed")
        })
        || value.get("success").and_then(Value::as_bool) == Some(false)
        || value
            .get("exit_code")
            .and_then(Value::as_i64)
            .is_some_and(|code| code != 0)
        || value
            .get("error")
            .is_some_and(|error| !error.is_null() && error.as_bool() != Some(false));
    failed.then(|| {
        failure_message(value)
            .unwrap_or("Cua reported a failed operation")
            .to_string()
    })
}

fn failure_message(value: &Value) -> Option<&str> {
    ["detail", "message", "error", "stderr"]
        .iter()
        .find_map(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
        })
        .or_else(|| {
            let error = value.get("error")?.as_object()?;
            ["detail", "message", "reason", "stderr"]
                .iter()
                .find_map(|field| {
                    error
                        .get(*field)
                        .and_then(Value::as_str)
                        .filter(|text| !text.trim().is_empty())
                })
        })
}

#[cfg(all(test, unix))]
mod diagnostic_process_tests {
    use super::*;
    async fn output(stdout: Value, stderr: &str, code: &str) -> Result<Vec<u8>, HostError> {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf '%s\\n' \"$1\"; printf '%s\\n' \"$2\" >&2; exit \"$3\"",
                "failure-output",
            ])
            .arg(stdout.to_string())
            .arg(stderr)
            .arg(code);
        run_command(command, Duration::from_secs(5), "failure-output").await
    }
    #[tokio::test]
    async fn failed_process_keeps_structured_error_and_warning_without_other_payload() {
        let error = output(serde_json::json!({"error":{"message":"container creation refused","environment":{"TOKEN":"must-not-appear"}},"unrelated":"must-not-appear"}), "disk warning", "1").await.unwrap_err().to_string();
        assert!(error.contains("container creation refused"));
        assert!(error.contains("stderr: disk warning"));
        assert!(error.contains("exit status: 1"));
        assert!(!error.contains("must-not-appear"));
    }
    #[tokio::test]
    async fn spaces_create_envelope_keeps_bounded_failure_and_accepts_successful_rows() {
        let error = output(
            serde_json::json!({"spaces":[
                {"error":format!("container engine: pull failed: input/output error {}", "x".repeat(2048))}
            ]}),
            "WARN low disk space: free after pull 14.2 GiB",
            "1",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("container engine: pull failed: input/output error"));
        assert!(error.contains("stderr: WARN low disk space: free after pull 14.2 GiB"));
        assert!(error.contains("exit status: 1"));
        assert!(error.len() < 1200);
        assert!(!error.contains("\"spaces\""));

        let success =
            serde_json::json!({"spaces":[{"id":"local:ready-space","name":"ready-space"}]});
        let bytes = output(success.clone(), "", "0").await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), success);
    }
    #[tokio::test]
    async fn failed_process_keeps_step_failure_and_bounds_both_streams() {
        let error = output(serde_json::json!([{"status":"ok","message":"unrelated"},{"status":"failed","detail":format!("failure {}", "x".repeat(2048))}]), &"w".repeat(2048), "1").await.unwrap_err().to_string();
        assert!(error.contains("failure "));
        assert!(error.contains("stderr: "));
        assert!(error.len() < 1200);
        assert!(!error.contains("unrelated"));
    }
    #[tokio::test]
    async fn ordinary_stderr_and_successful_json_keep_existing_behavior() {
        let error = output(
            serde_json::json!({"unrelated":"must-not-appear"}),
            "ordinary process error",
            "1",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("ordinary process error"));
        assert!(!error.contains("must-not-appear"));
        let success = serde_json::json!({"status":"ready","value":7});
        let bytes = output(success.clone(), "a warning", "0").await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), success);
        assert!(
            output(
                serde_json::json!({"success":false,"error":{"message":"failed setup step"}}),
                "",
                "0"
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("failed setup step")
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn an_unowned_existing_guest_cannot_be_adopted() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("cua-fixture");
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        let manager = CuaSpaceManager::open(&binary, temp.path().join("state")).unwrap();
        let name = CuaSpaceManager::name(&manager.namespace, "proof-agent");
        std::fs::write(&binary, format!("#!/bin/sh\ncase \"$*\" in\n  *'sb ls --local --no-size') printf '%s\\n' '[{{\"name\":\"{name}\"}}]';;\n  *) exit 90;;\nesac\n")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            manager
                .ensure_agent_space("proof-agent", SpaceResources::default())
                .await,
            Err(HostError::Forbidden)
        ));
        assert!(!manager.receipt("proof-agent").exists());
    }
    #[test]
    fn one_provisioner_owns_the_registry_until_it_closes() {
        let temp = tempfile::tempdir().unwrap();
        let first = CuaSpaceManager::open("/bin/sh", temp.path()).unwrap();
        assert!(matches!(
            CuaSpaceManager::open("/bin/sh", temp.path()),
            Err(HostError::Busy)
        ));
        drop(first);
        CuaSpaceManager::open("/bin/sh", temp.path()).unwrap();
    }

    #[test]
    fn legacy_owner_lock_and_resource_identity_survive_harness_rename() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().join("proxy-agent-owners");
        std::fs::create_dir_all(&owner).unwrap();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(owner.join("manager.lock"))
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        assert!(matches!(
            CuaSpaceManager::open("/bin/sh", temp.path()),
            Err(HostError::Busy)
        ));
        drop(lock);
        let manager = CuaSpaceManager::open("/bin/sh", temp.path()).unwrap();
        let name = CuaSpaceManager::name(&manager.namespace, "existing-agent");
        assert!(name.starts_with("proxy-agent-"));
        assert_eq!(
            manager.receipt("existing-agent"),
            owner.join(format!("{name}.json"))
        );
        assert!(!temp.path().join("proxy-harness-owners").exists());
    }
}
