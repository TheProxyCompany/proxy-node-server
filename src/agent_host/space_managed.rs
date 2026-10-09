//! Recovery for the existing Cua 0.4.1 managed Linux runtime after host reboot.
//! The pinned CLI's `spaces start` asks status before booting the VM, and status
//! says "missing" after an unclean stop. Boot the existing profile first, using
//! the same isolated invocation as upstream `cua_vmm::managed::start_once`:
//! https://github.com/trycua/cua/blob/cua-sdk-v0.4.1/libs/cua/crates/cua-vmm/src/managed.rs
//! This does not install a runtime, write configuration, or recreate a guest.

use super::HostError;
#[cfg(target_os = "macos")]
use std::path::Path;

pub(super) async fn backend_healthy(
    home: &std::path::Path,
    kind: &super::LocalSpaceKind,
    report: &serde_json::Value,
) -> Result<bool, HostError> {
    #[cfg(target_os = "macos")]
    if *kind == super::LocalSpaceKind::LinuxContainer && managed_selected(report)? {
        return Ok(home
            .join("runtimes/linux/vm/_lima/colima-cua/lima.yaml")
            .is_file()
            && macos::engine_healthy(home).await);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = home;
    let name = match kind {
        super::LocalSpaceKind::LinuxContainer => "container",
        super::LocalSpaceKind::MacosVm => "lume",
    };
    Ok(report
        .get("backends")
        .and_then(serde_json::Value::as_array)
        .and_then(|backends| backends.iter().find(|backend| backend["backend"] == name))
        .and_then(|backend| backend.get("ready"))
        .and_then(serde_json::Value::as_bool)
        == Some(true))
}

#[cfg(not(target_os = "macos"))]
pub(super) async fn ensure_existing(_manager: &super::CuaSpaceManager) -> Result<(), HostError> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) async fn ensure_existing(manager: &super::CuaSpaceManager) -> Result<(), HostError> {
    if !manager
        .home
        .join("runtimes/linux/vm/_lima/colima-cua/lima.yaml")
        .try_exists()?
    {
        return Ok(());
    }
    // Respect Cua's configured engine, including an explicit system choice.
    // Its doctor is read-only; a stale Docker context does not supersede an
    // existing managed runtime in Cua's normal `auto` selection.
    let report = manager.json(&["runtime".into(), "doctor".into()]).await?;
    if !managed_selected(&report)? {
        return Ok(());
    }
    macos::ensure(
        &manager.home,
        std::time::Duration::from_secs(600),
        std::time::Duration::from_secs(90),
    )
    .await
}

#[cfg(target_os = "macos")]
fn managed_selected(report: &serde_json::Value) -> Result<bool, HostError> {
    let managed = report
        .get("backends")
        .and_then(serde_json::Value::as_array)
        .and_then(|backends| {
            backends
                .iter()
                .find(|backend| backend["backend"] == "managed")
        })
        .ok_or_else(|| {
            HostError::Invalid(
                "Cua did not report the existing managed Linux runtime's state".into(),
            )
        })?;
    match (
        managed.get("ready").and_then(serde_json::Value::as_bool),
        managed
            .get("provisionable")
            .and_then(serde_json::Value::as_bool),
    ) {
        (Some(ready), Some(provisionable)) => Ok(ready || provisionable),
        _ => Err(HostError::Invalid(
            "Cua returned an invalid managed Linux runtime state".into(),
        )),
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::process::Command;

    const TOOLS: &str = "colima-0.10.3-lima-2.2.0";
    const VERIFIED: &str = "colima 0.10.3\nlima 2.2.0\n";

    /// Called only for a validated ownership receipt, while the cross-profile
    /// provisioning lock is held. `CUA_HOME` is Node's owned, physical home.
    pub(super) async fn ensure(
        home: &Path,
        boot_timeout: Duration,
        ready_timeout: Duration,
    ) -> Result<(), HostError> {
        let root = home.join("runtimes/linux");
        let profile = root.join("vm/_lima/colima-cua/lima.yaml");
        if !profile.try_exists()? {
            // A system container engine or a first install has no managed VM
            // to resume. Never synthesize its assets or select another engine.
            return Ok(());
        }
        let owner = std::fs::symlink_metadata(home)?.uid();
        checked(home, home, owner, false)?;
        for directory in [
            "runtimes",
            "runtimes/linux",
            "runtimes/linux/vm",
            "runtimes/linux/vm/cua",
            "runtimes/linux/vm/_lima",
            "runtimes/linux/vm/_lima/colima-cua",
            "runtimes/linux/vm/_lima/_disks",
            "runtimes/linux/vm/_lima/_disks/colima-cua",
            "runtimes/linux/home",
        ] {
            checked(home, &home.join(directory), owner, false)?;
        }
        let tools = root.join(TOOLS);
        for directory in [
            &tools,
            &tools.join("bin"),
            &tools.join("lima"),
            &tools.join("lima/bin"),
        ] {
            checked(home, directory, owner, false)?;
        }
        for file in [
            &profile,
            &root.join("vm/_lima/colima-cua/disk"),
            &root.join("vm/_lima/_disks/colima-cua/datadisk"),
            &root.join("vm/cua/colima.yaml"),
            &tools.join(".verified"),
            &tools.join("bin/colima"),
            &tools.join("lima/bin/limactl"),
        ] {
            checked(home, file, owner, true)?;
        }
        // Colima 0.10.3 creates and formats a runtime data disk when it
        // cannot find the existing one. Both persisted disks must survive.
        for disk in [
            "vm/_lima/colima-cua/disk",
            "vm/_lima/_disks/colima-cua/datadisk",
        ] {
            if std::fs::metadata(root.join(disk))?.len() == 0 {
                return Err(HostError::Invalid("An existing managed Linux runtime disk is empty; explicit recovery is required".into()));
            }
        }
        checked_docker_config(home, &root.join("home/.docker"), owner)?;
        if std::fs::read_to_string(tools.join(".verified"))? != VERIFIED {
            return Err(HostError::Invalid("The existing managed Linux runtime does not match the pinned Colima/Lima tools; explicit recovery is required".into()));
        }
        let socket = root.join("vm/cua/docker.sock");
        if running(&socket).await {
            return Ok(());
        }
        let mut command = Command::new(tools.join("bin/colima"));
        command
            .args(["--profile", "cua", "start"])
            .env_clear()
            .env("HOME", root.join("home"))
            .env("COLIMA_HOME", root.join("vm"))
            .env("LIMA_HOME", root.join("vm/_lima"))
            .env("DOCKER_CONFIG", root.join("home/.docker"))
            .env("PATH", path(&tools))
            .env("TMPDIR", std::env::temp_dir())
            .stdin(Stdio::null());
        for name in ["USER", "LOGNAME", "LANG"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        // No disk-image flags, config writes, global context changes, or
        // upstream's force-stop fallback: other Proxy profiles share this VM.
        super::super::run_command(
            command,
            boot_timeout,
            "Starting the existing managed Linux runtime",
        )
        .await?;
        let deadline = tokio::time::Instant::now() + ready_timeout;
        loop {
            if running(&socket).await {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(HostError::Invalid("The existing managed Linux runtime started but its engine did not become reachable; existing guests were preserved".into()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn path(tools: &Path) -> std::ffi::OsString {
        std::env::join_paths([
            tools.join("bin"),
            tools.join("lima/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/sbin"),
        ])
        .expect("fixed runtime paths")
    }

    async fn running(socket: &Path) -> bool {
        let ping = async {
            let mut stream = UnixStream::connect(socket).await?;
            stream
                .write_all(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await?;
            let mut response = Vec::new();
            stream.take(4097).read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response.len() <= 4096 && docker_ping_ok(&response))
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(1), ping).await,
            Ok(Ok(true))
        )
    }

    pub(super) async fn engine_healthy(home: &Path) -> bool {
        running(&home.join("runtimes/linux/vm/cua/docker.sock")).await
    }

    fn docker_ping_ok(response: &[u8]) -> bool {
        let Some(end) = response.windows(4).position(|part| part == b"\r\n\r\n") else {
            return false;
        };
        let Ok(headers) = std::str::from_utf8(&response[..end]) else {
            return false;
        };
        let Some(status) = headers.lines().next() else {
            return false;
        };
        let mut words = status.split_ascii_whitespace();
        matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1"))
            && words.next() == Some("200")
            && response[end + 4..] == *b"OK"
    }

    fn checked_docker_config(home: &Path, directory: &Path, owner: u32) -> Result<(), HostError> {
        match std::fs::symlink_metadata(directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => checked(home, directory, owner, false)?,
        }
        // A config.json or context symlink can escape even when .docker itself
        // is a real directory. Metadata only; never read stored credentials.
        let mut pending = vec![directory.to_path_buf()];
        let mut entries = 0;
        while let Some(path) = pending.pop() {
            entries += 1;
            if entries > 1024 {
                return Err(HostError::Invalid("The managed runtime's isolated Docker configuration exceeds its bounded validation limit".into()));
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            checked(home, &path, owner, !metadata.is_dir())?;
            if metadata.is_dir() {
                for entry in std::fs::read_dir(path)? {
                    pending.push(entry?.path());
                }
            }
        }
        Ok(())
    }

    fn checked(home: &Path, path: &Path, owner: u32, file: bool) -> Result<(), HostError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || metadata.mode() & 0o022 != 0
            || (file && !metadata.is_file())
            || (!file && !metadata.is_dir())
            || path.canonicalize()? != path
            || !path.starts_with(home)
        {
            return Err(HostError::Invalid("The existing managed Linux runtime has an unexpected owner, path or writable asset; explicit recovery is required".into()));
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "space_managed_tests.rs"]
mod tests;
