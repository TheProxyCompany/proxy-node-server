//! Local Cua provisioning. Ownership is recorded before creation so an
//! interrupted request can recover without adopting another user's desktop.
//! Cua CLI/core SDK are MIT; the separately installed spacesd is FSL-1.1-MIT.
//! This module calls the installed service and does not vendor its source.

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
use tokio::io::AsyncReadExt;
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

#[derive(Serialize, Deserialize)]
struct Ownership {
    version: u32,
    agent_id: String,
    name: String,
    resources: SpaceResources,
}

#[derive(Clone)]
pub struct CuaSpaceManager {
    binary: PathBuf,
    root: PathBuf,
    _lease: Arc<File>,
    mutation: Arc<Mutex<()>>,
}

impl CuaSpaceManager {
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
        private_directory(&root.join("proxy-agent-owners"))?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lease = options.open(root.join("proxy-agent-owners/manager.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lease).map_err(|_| HostError::Busy)?;
        Ok(Self {
            binary: binary.into(),
            root: root.into(),
            _lease: Arc::new(lease),
            mutation: Arc::new(Mutex::new(())),
        })
    }

    fn name(agent: &str) -> String {
        let hash = Sha256::digest(agent.as_bytes());
        format!(
            "proxy-agent-{}",
            hash[..12]
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        )
    }
    fn receipt(&self, agent: &str) -> PathBuf {
        self.root
            .join("proxy-agent-owners")
            .join(format!("{}.json", Self::name(agent)))
    }
    fn load_owner(&self, agent: &str) -> Result<Ownership, HostError> {
        let owner: Ownership = serde_json::from_slice(&std::fs::read(self.receipt(agent))?)?;
        if owner.version != 1 || owner.agent_id != agent || owner.name != Self::name(agent) {
            return Err(HostError::Invalid(
                "Cua Space ownership record does not match agent".into(),
            ));
        }
        Ok(owner)
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
            ("CUA_HOME".into(), self.root.to_string_lossy().into_owned()),
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
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(HostError::Stopped)?
            .take(4 * 1024 * 1024 + 1);
        let result = tokio::time::timeout(timeout, async {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(HostError::Invalid("Cua response exceeded 4 MiB".into()));
            }
            if !child.wait().await?.success() {
                return Err(HostError::Invalid(
                    "local Cua command failed; inspect Cua's local status".into(),
                ));
            }
            Ok(bytes)
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => Err(HostError::Invalid(
                "local Cua command timed out; inspect before retrying".into(),
            )),
        }
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
        let name = Self::name(agent);
        let exists = self.listed(&name).await?;
        let receipt = self.receipt(agent);
        if receipt.exists() {
            let owner = self.load_owner(agent)?;
            if owner.resources != resources {
                return Err(HostError::Invalid(
                    "Space resources changed; stop and explicitly migrate the existing guest"
                        .into(),
                ));
            }
        } else {
            if exists {
                return Err(HostError::Forbidden);
            }
            let owner = Ownership {
                version: 1,
                agent_id: agent.into(),
                name: name.clone(),
                resources: resources.clone(),
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
            file.write_all(&serde_json::to_vec(&owner)?)?;
            file.sync_all()?;
            File::open(receipt.parent().expect("receipt has parent"))?.sync_all()?;
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
                    &["sb".into(), "start".into(), id.clone()],
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
            workspace_root,
            endpoint,
        };
        binding.validate()?;
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
    pub async fn stop_agent_space(&self, agent: &str) -> Result<(), HostError> {
        let _guard = self.mutation.lock().await;
        let owner = self.load_owner(agent)?;
        self.run(
            &["sb".into(), "stop".into(), format!("local:{}", owner.name)],
            Duration::from_secs(120),
        )
        .await?;
        Ok(())
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
        let name = CuaSpaceManager::name("proof-agent");
        std::fs::write(&binary, format!("#!/bin/sh\ncase \"$*\" in\n  *'sb ls --local --no-size') printf '%s\\n' '[{{\"name\":\"{name}\"}}]';;\n  *) exit 90;;\nesac\n")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let manager = CuaSpaceManager::open(&binary, temp.path().join("state")).unwrap();
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
}
