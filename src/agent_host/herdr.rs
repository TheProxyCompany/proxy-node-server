//! Herdr interoperability without making it a second owner of the root.
//! Uses the documented 0.9.2+ report/release CLI; no terminal scraping.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::process::Command;
use tokio::sync::watch;

use super::HostError;

pub struct HerdrBridge {
    binary: PathBuf,
    socket: String,
    pane: String,
    agent: String,
    sequence: AtomicU64,
    resume: Vec<String>,
}

impl HerdrBridge {
    /// A resume command must attach to the already hosted root, not start a
    /// second runtime. Never put a credential in its arguments.
    pub fn new(
        binary: PathBuf,
        socket: String,
        pane: String,
        agent: String,
        resume: Vec<String>,
    ) -> Result<Self, HostError> {
        if !binary.is_absolute() || socket.is_empty() || pane.is_empty() || !super::valid_id(&agent)
        {
            return Err(HostError::Invalid("invalid Herdr attachment".into()));
        }
        if resume.len() > 64
            || resume.iter().map(String::len).sum::<usize>() > 8192
            || resume
                .iter()
                .any(|s| s.contains('\'') || s.chars().any(char::is_control))
            || resume
                .first()
                .is_some_and(|s| s.is_empty() || s.contains('/') || s.contains('\\'))
        {
            return Err(HostError::Invalid(
                "Herdr resume command must be a plain executable name and bounded safe arguments"
                    .into(),
            ));
        }
        Ok(Self {
            binary,
            socket,
            pane,
            agent,
            sequence: AtomicU64::new(0),
            resume,
        })
    }

    pub fn from_environment(env: &BTreeMap<String, String>, agent: &str) -> Option<Self> {
        let value = |name: &str| env.get(name).cloned().or_else(|| std::env::var(name).ok());
        if value("HERDR_ENV").as_deref() != Some("1") {
            return None;
        }
        let resume = value("PROXY_HARNESS_HERDR_RESUME_ARGV")
            .or_else(|| value("PROXY_AGENT_HERDR_RESUME_ARGV"))
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        Self::new(
            value("HERDR_BIN_PATH")?.into(),
            value("HERDR_SOCKET_PATH")?,
            value("HERDR_PANE_ID")?,
            agent.into(),
            resume,
        )
        .ok()
    }

    fn next_sequence(&self) -> u64 {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let mut previous = self.sequence.load(Ordering::SeqCst);
        loop {
            let next = previous.saturating_add(1).max(time);
            match self.sequence.compare_exchange_weak(
                previous,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return next,
                Err(current) => previous = current,
            }
        }
    }

    pub async fn report(&self, state: &str) -> Result<(), HostError> {
        if !matches!(state, "working" | "idle" | "blocked") {
            return Err(HostError::Invalid("invalid Herdr state".into()));
        }
        let mut command = self.command("report-agent");
        command.args(["--state", state, "--seq", &self.next_sequence().to_string()]);
        if !self.resume.is_empty() {
            command
                .args(["--agent-session-id", &self.agent, "--"])
                .args(&self.resume);
        }
        self.run(command).await
    }

    pub async fn release(&self) -> Result<(), HostError> {
        let mut command = self.command("release-agent");
        command.args(["--seq", &self.next_sequence().to_string()]);
        self.run(command).await
    }

    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.binary);
        super::scrub_harness_environment(&mut command);
        command
            .args([
                "pane",
                operation,
                &self.pane,
                "--source",
                &format!("proxy-harness-host:{}", self.agent),
                "--agent",
                &self.agent,
            ])
            .env("HERDR_SOCKET_PATH", &self.socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command
    }

    async fn run(&self, mut command: Command) -> Result<(), HostError> {
        let status = tokio::time::timeout(Duration::from_secs(1), command.status())
            .await
            .map_err(|_| HostError::AcceptanceUnknown)??;
        if status.success() {
            Ok(())
        } else {
            Err(HostError::Rejected(
                "Herdr did not accept the report".into(),
            ))
        }
    }

    /// One background reporter, latest state wins. Herdr availability cannot
    /// block the agent or the durable output/acceptance path.
    pub fn start(self: Arc<Self>) -> watch::Sender<Option<String>> {
        let (sender, mut receiver) = watch::channel(Some("idle".to_string()));
        tokio::spawn(async move {
            loop {
                let state = receiver.borrow_and_update().clone();
                match state {
                    Some(state) => {
                        let _ = self.report(&state).await;
                    }
                    None => {
                        let _ = self.release().await;
                        break;
                    }
                }
                if receiver.changed().await.is_err() {
                    let _ = self.release().await;
                    break;
                }
            }
        });
        sender
    }
}

pub(crate) fn state_for(event: &Value) -> Option<String> {
    match event.get("type").and_then(Value::as_str)? {
        "accepted" => Some("working".into()),
        "agent_settled" => Some(
            if event["status"] == "blocked" {
                "blocked"
            } else {
                "idle"
            }
            .into(),
        ),
        "root_state" => Some(
            match event["status"].as_str() {
                Some("running") => "working",
                Some("blocked") => "blocked",
                _ => "idle",
            }
            .into(),
        ),
        _ => None,
    }
}
