//! Cross-platform `cloudflared` tunnel process manager for `<name>.proxy.ing`.

pub mod install;

use std::net::TcpListener as StdTcpListener;
use std::num::TryFromIntError;
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: String,
    pub username: String,
    pub tunnel_token: String,
    pub local_port: i32,
    pub metrics_port: i32,
    pub enabled: bool,
    pub updated_at: String,
}

pub trait TunnelConfigSource: Send + Sync + 'static {
    fn load_config(&self) -> Result<Option<TunnelConfig>, String>;
}

#[derive(Debug, Clone)]
pub enum TunnelState {
    Stopped,
    Starting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgress {
    pub phase: String,
    pub progress: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub state: String,
    pub error_message: Option<String>,
    pub username: Option<String>,
    pub local_port: Option<i32>,
    pub metrics_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<InstallProgress>,
}

const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(5);
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(120);
const MAX_RESTART_ATTEMPTS: u32 = 10;

pub fn restart_delay(attempt: u32) -> Option<Duration> {
    (1..=MAX_RESTART_ATTEMPTS)
        .contains(&attempt)
        .then(|| exponential_backoff_interval(RESTART_BACKOFF_BASE, RESTART_BACKOFF_MAX, attempt))
}

static MANAGER: OnceLock<Arc<TunnelManager>> = OnceLock::new();

pub fn install(manager: Arc<TunnelManager>) {
    let _ = MANAGER.set(manager);
}

pub fn manager() -> Option<Arc<TunnelManager>> {
    MANAGER.get().map(Arc::clone)
}

pub struct TunnelManager {
    state: RwLock<TunnelState>,
    install_state: RwLock<Option<InstallProgress>>,
    active_metrics_port: RwLock<Option<i32>>,
    lifecycle: Mutex<()>,
    child: Mutex<Option<Child>>,
    start_task: Mutex<Option<JoinHandle<()>>>,
    health_task: Mutex<Option<JoinHandle<()>>>,
    generation: AtomicU64,
    restart_attempts: AtomicU32,
    config_source: Arc<dyn TunnelConfigSource>,
}

impl TunnelManager {
    pub fn new(config_source: Arc<dyn TunnelConfigSource>) -> Self {
        Self {
            state: RwLock::new(TunnelState::Stopped),
            install_state: RwLock::new(None),
            active_metrics_port: RwLock::new(None),
            lifecycle: Mutex::new(()),
            child: Mutex::new(None),
            start_task: Mutex::new(None),
            health_task: Mutex::new(None),
            generation: AtomicU64::new(0),
            restart_attempts: AtomicU32::new(0),
            config_source,
        }
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), String> {
        self.restart_attempts.store(0, Ordering::Release);
        self.start_from_config(None).await
    }

    async fn start_from_config(
        self: &Arc<Self>,
        only_if_generation: Option<u64>,
    ) -> Result<(), String> {
        let _lifecycle = self.lifecycle.lock().await;
        if only_if_generation.is_some_and(|generation| !self.is_current_generation(generation)) {
            return Ok(());
        }
        let config = self.load_config().await?;
        let config = match config {
            Some(config) => config,
            None => {
                let message = "Tunnel is not configured yet".to_string();
                self.set_state(TunnelState::Error(message.clone())).await;
                return Err(message);
            }
        };
        if config.username.trim().is_empty() {
            let message = "Tunnel config username cannot be empty".to_string();
            self.set_state(TunnelState::Error(message.clone())).await;
            return Err(message);
        }
        if config.tunnel_token.trim().is_empty() {
            let message = "Tunnel config token cannot be empty".to_string();
            self.set_state(TunnelState::Error(message.clone())).await;
            return Err(message);
        }
        if only_if_generation.is_some() && !config.enabled {
            return Ok(());
        }

        let mut start_task = self.start_task.lock().await;
        {
            let state = self.state.read().await;
            if matches!(*state, TunnelState::Starting | TunnelState::Connected) {
                return Ok(());
            }
        }
        if let Some(previous) = start_task.take() {
            previous.abort();
        }
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.set_state(TunnelState::Starting).await;

        let manager = Arc::clone(self);
        *start_task = Some(tokio::spawn(async move {
            manager.start_inner(config, generation).await;
        }));

        Ok(())
    }

    async fn start_inner(self: Arc<Self>, config: TunnelConfig, generation: u64) {
        let cloudflared_path = match self.which_cloudflared().await {
            Ok(path) => path,
            Err(err) => {
                self.set_error_if_current(generation, err).await;
                return;
            }
        };
        if !self.is_current_generation(generation) {
            return;
        }
        reap_orphaned_cloudflared(&cloudflared_path).await;
        let metrics_port = match select_metrics_port(config.metrics_port) {
            Ok(port) => port,
            Err(err) => {
                self.set_error_if_current(generation, err).await;
                return;
            }
        };
        if !self.is_current_generation(generation) {
            return;
        }

        let mut command = Command::new(cloudflared_path);
        command
            .arg("--protocol")
            .arg("http2")
            .arg("--metrics")
            .arg(format!("127.0.0.1:{}", metrics_port))
            .arg("--no-autoupdate")
            .arg("tunnel")
            .arg("run")
            .arg("--token")
            .arg(config.tunnel_token.trim())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                let message = format!("Failed to start cloudflared: {}", err);
                self.set_error_if_current(generation, message).await;
                return;
            }
        };

        if !self.is_current_generation(generation) {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return;
        }

        let pid = child.id();
        if let Some(stdout) = child.stdout.take() {
            spawn_pipe_logger(pid, "stdout", stdout);
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_pipe_logger(pid, "stderr", stderr);
        }

        {
            let mut child_guard = self.child.lock().await;
            if let Some(mut existing) = child_guard.take() {
                let _ = existing.kill().await;
                let _ = existing.wait().await;
            }
            *child_guard = Some(child);
        }

        *self.active_metrics_port.write().await = Some(metrics_port);

        {
            let mut health_guard = self.health_task.lock().await;
            if let Some(handle) = health_guard.take() {
                handle.abort();
            }
            let manager = Arc::clone(&self);
            *health_guard = Some(tokio::spawn(async move {
                TunnelManager::run_health_loop(manager, metrics_port).await;
            }));
        }
    }

    pub async fn stop(self: &Arc<Self>) -> Result<(), String> {
        let _lifecycle = self.lifecycle.lock().await;

        let start_task = {
            let mut start_task = self.start_task.lock().await;
            self.generation.fetch_add(1, Ordering::AcqRel);
            start_task.take()
        };
        if let Some(start_task) = start_task {
            start_task.abort();
            let _ = start_task.await;
        }

        {
            let mut health_guard = self.health_task.lock().await;
            if let Some(handle) = health_guard.take() {
                handle.abort();
            }
        }

        let child_opt = {
            let mut child_guard = self.child.lock().await;
            child_guard.take()
        };

        if let Some(mut child) = child_opt {
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                let _ = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            }
            if tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .is_err()
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }

        self.set_state(TunnelState::Stopped).await;
        *self.active_metrics_port.write().await = None;
        Ok(())
    }

    pub async fn status(&self) -> Result<TunnelStatus, String> {
        let (state, error_message) = {
            let state = self.state.read().await;
            state_fields(&state)
        };
        let config = self.load_config().await?;
        let install = self.install_state.read().await.clone();
        let active_metrics_port = *self.active_metrics_port.read().await;

        Ok(TunnelStatus {
            state: state.to_string(),
            error_message,
            username: config.as_ref().map(|cfg| cfg.username.clone()),
            local_port: config.as_ref().map(|cfg| cfg.local_port),
            metrics_port: active_metrics_port.or(config.as_ref().map(|cfg| cfg.metrics_port)),
            install,
        })
    }

    pub(crate) async fn set_install_state(&self, progress: Option<InstallProgress>) {
        *self.install_state.write().await = progress;
    }

    fn is_current_generation(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
    }

    async fn set_error_if_current(&self, generation: u64, message: String) {
        if self.is_current_generation(generation) {
            self.set_state(TunnelState::Error(message)).await;
        }
    }

    async fn load_config(&self) -> Result<Option<TunnelConfig>, String> {
        let source = Arc::clone(&self.config_source);
        tokio::task::spawn_blocking(move || source.load_config())
            .await
            .map_err(|e| format!("Failed to join tunnel config task: {}", e))?
    }

    async fn set_state(&self, state: TunnelState) -> bool {
        let mut guard = self.state.write().await;
        let changed = !matches!(
            (&*guard, &state),
            (TunnelState::Connected, TunnelState::Connected)
                | (TunnelState::Stopped, TunnelState::Stopped)
                | (TunnelState::Starting, TunnelState::Starting)
        );
        *guard = state;
        changed
    }

    async fn run_health_loop(manager: Arc<Self>, metrics_port: i32) {
        let client = reqwest::Client::new();
        let ready_url = format!("http://127.0.0.1:{}/ready", metrics_port);

        const UNHEALTHY_INTERVAL_BASE: Duration = Duration::from_secs(5);
        const UNHEALTHY_INTERVAL_MAX: Duration = Duration::from_secs(60);
        const HEALTHY_INTERVAL: Duration = Duration::from_secs(60);
        let mut consecutive_probe_failures = 0_u32;

        loop {
            let child_state = {
                let mut child_guard = manager.child.lock().await;
                match child_guard.as_mut() {
                    Some(child) => match child.try_wait() {
                        Ok(Some(status)) => {
                            child_guard.take();
                            Some(Err(format!("cloudflared exited with status {}", status)))
                        }
                        Ok(None) => Some(Ok(())),
                        Err(err) => {
                            child_guard.take();
                            Some(Err(format!("Failed to poll cloudflared process: {}", err)))
                        }
                    },
                    None => None,
                }
            };

            match child_state {
                Some(Ok(())) => {}
                Some(Err(message)) => {
                    manager.set_state(TunnelState::Error(message)).await;
                    manager.schedule_restart();
                    break;
                }
                None => break,
            }

            let is_ready = client
                .get(&ready_url)
                .send()
                .await
                .map(|response| response.status().is_success())
                .unwrap_or(false);

            let sleep_duration = if is_ready {
                consecutive_probe_failures = 0;
                manager.restart_attempts.store(0, Ordering::Release);
                manager.set_state(TunnelState::Connected).await;
                HEALTHY_INTERVAL
            } else {
                consecutive_probe_failures = consecutive_probe_failures.saturating_add(1);
                manager.set_state(TunnelState::Starting).await;
                exponential_backoff_interval(
                    UNHEALTHY_INTERVAL_BASE,
                    UNHEALTHY_INTERVAL_MAX,
                    consecutive_probe_failures,
                )
            };

            tokio::time::sleep(sleep_duration).await;
        }

        *manager.active_metrics_port.write().await = None;
    }

    fn schedule_restart(self: &Arc<Self>) {
        let generation = self.generation.load(Ordering::Acquire);
        let attempt = self.restart_attempts.fetch_add(1, Ordering::AcqRel) + 1;
        let Some(delay) = restart_delay(attempt) else {
            return;
        };
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = manager.start_from_config(Some(generation)).await;
        });
    }
}

pub fn state_fields(state: &TunnelState) -> (&'static str, Option<String>) {
    match state {
        TunnelState::Stopped => ("stopped", None),
        TunnelState::Starting => ("starting", None),
        TunnelState::Connected => ("connected", None),
        TunnelState::Error(message) => ("error", Some(message.clone())),
    }
}

pub fn exponential_backoff_interval(
    base: Duration,
    max: Duration,
    consecutive_failures: u32,
) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(5);
    let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    let interval = base.saturating_mul(multiplier);
    if interval > max { max } else { interval }
}

pub async fn reap_orphaned_cloudflared(binary_path: &str) {
    let Ok(output) = Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .await
    else {
        return;
    };
    let listing = String::from_utf8_lossy(&output.stdout).into_owned();
    for pid in orphaned_cloudflared_pids(&listing, binary_path) {
        #[cfg(unix)]
        unsafe {
            let _ = libc::kill(pid, libc::SIGKILL);
        }
    }
}

pub fn orphaned_cloudflared_pids(listing: &str, binary_path: &str) -> Vec<i32> {
    listing
        .lines()
        .filter_map(|line| {
            let (pid, rest) = line.trim_start().split_once(char::is_whitespace)?;
            let (ppid, command) = rest.trim_start().split_once(char::is_whitespace)?;
            let pid: i32 = pid.parse().ok()?;
            let ppid: i32 = ppid.parse().ok()?;
            let command = command.trim_start();
            let runs_our_binary = command == binary_path
                || command
                    .strip_prefix(binary_path)
                    .is_some_and(|args| args.starts_with(' '));
            (ppid == 1 && runs_our_binary).then_some(pid)
        })
        .collect()
}

pub fn select_metrics_port(preferred_port: i32) -> Result<i32, String> {
    let preferred_port = u16::try_from(preferred_port).map_err(metrics_port_range_error)?;
    if preferred_port == 0 {
        return Err("Invalid cloudflared metrics port: port must be in 1...65535".to_string());
    }

    for offset in 0..=4_u16 {
        let Some(candidate_port) = preferred_port.checked_add(offset) else {
            break;
        };
        if let Ok(listener) = StdTcpListener::bind(("127.0.0.1", candidate_port)) {
            drop(listener);
            return Ok(i32::from(candidate_port));
        }
    }

    let listener = StdTcpListener::bind(("127.0.0.1", 0)).map_err(|err| {
        format!(
            "Failed to reserve cloudflared metrics port near {}: {}",
            preferred_port, err
        )
    })?;
    let fallback_port = listener
        .local_addr()
        .map_err(|err| {
            format!(
                "Failed to read fallback cloudflared metrics port near {}: {}",
                preferred_port, err
            )
        })?
        .port();
    drop(listener);
    Ok(i32::from(fallback_port))
}

fn metrics_port_range_error(err: TryFromIntError) -> String {
    format!("Invalid cloudflared metrics port: {}", err)
}

fn spawn_pipe_logger<R>(_pid: Option<u32>, _stream: &'static str, reader: R)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(_)) = lines.next_line().await {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_metrics_port_skips_busy_preferred_port() {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).unwrap();
        let preferred_port = listener.local_addr().unwrap().port();
        let selected_port = select_metrics_port(i32::from(preferred_port)).unwrap();

        assert_ne!(selected_port, i32::from(preferred_port));
        assert!((1..=65_535).contains(&selected_port));
    }
}
