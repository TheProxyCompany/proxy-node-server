//! Typed admission fencing before an agent's durable state changes hosts.
use super::{AgentHost, HostError};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::oneshot;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandoffState {
    pub handoff_id: String,
    pub admission: String,
    pub ready: bool,
    pub durable: bool,
    #[serde(default)]
    pub assessment_pending: bool,
    #[serde(default)]
    pub active_input: Option<String>,
    pub accepted_pending: Option<u64>,
    pub active_processes: Option<u64>,
    pub unknown_effects: Option<u64>,
    #[serde(default)]
    pub cursors: Value,
    #[serde(default)]
    pub reason: Option<String>,
}
impl HandoffState {
    /// Null/unassessed counts or a pid-only idle claim are never a checkpoint.
    pub fn verified(&self) -> bool {
        let receipt = |name: &str| {
            self.cursors.get(name).is_some_and(|cursor| {
                cursor.get("bytes").and_then(Value::as_u64).is_some()
                    && cursor
                        .get("sha256")
                        .and_then(Value::as_str)
                        .is_some_and(|hash| {
                            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
            })
        };
        self.admission == "paused"
            && self.ready
            && self.durable
            && !self.assessment_pending
            && !self.handoff_id.is_empty()
            && self.active_input.is_none()
            && self.accepted_pending == Some(0)
            && self.active_processes == Some(0)
            && self.unknown_effects == Some(0)
            && receipt("inbox")
            && receipt("journal")
            && self
                .cursors
                .pointer("/journal/sequence")
                .and_then(Value::as_u64)
                .is_some()
            && self
                .cursors
                .pointer("/journal/journal_id")
                .and_then(Value::as_str)
                .is_some_and(|id| {
                    !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
                })
    }
}

pub(super) fn is_command(value: &Value) -> bool {
    value
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|name| matches!(name, "prepare_handoff" | "handoff_status" | "resume"))
}

impl AgentHost {
    pub async fn prepare_handoff(
        &self,
        agent: &str,
        handoff_id: &str,
    ) -> Result<HandoffState, HostError> {
        self.handoff_command(agent, handoff_id, "prepare_handoff")
            .await
    }
    pub async fn handoff_status(
        &self,
        agent: &str,
        handoff_id: &str,
    ) -> Result<HandoffState, HostError> {
        self.handoff_command(agent, handoff_id, "handoff_status")
            .await
    }
    pub async fn resume(&self, agent: &str, handoff_id: &str) -> Result<HandoffState, HostError> {
        self.handoff_command(agent, handoff_id, "resume").await
    }
    async fn handoff_command(
        &self,
        id: &str,
        handoff_id: &str,
        command: &str,
    ) -> Result<HandoffState, HostError> {
        if handoff_id.is_empty()
            || handoff_id.len() > 256
            || handoff_id.chars().any(char::is_control)
        {
            return Err(HostError::Invalid(
                "A bounded stable handoff id is required".into(),
            ));
        }
        let agent = self.agent(id)?;
        self.ensure_started(id).await?;
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let request_id = format!(
            "host-control-{}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let wire = json!({"type":command,"id":request_id,"handoff_id":handoff_id});
        let (sender, response) = oneshot::channel();
        agent
            .acknowledgements
            .lock()
            .unwrap()
            .insert(request_id.clone(), vec![sender]);
        let result = async {
            agent.write(&wire).await?;
            match tokio::time::timeout(Duration::from_secs(30), response).await {
                Ok(Ok(Ok(reply))) => {
                    let state: HandoffState =
                        serde_json::from_value(reply.get("data").cloned().ok_or_else(|| {
                            HostError::Invalid("Handoff reply has no typed state".into())
                        })?)?;
                    if state.handoff_id != handoff_id {
                        return Err(HostError::Invalid(
                            "Handoff reply belongs to another transfer".into(),
                        ));
                    }
                    Ok(state)
                }
                Ok(Ok(Err(error))) => Err(HostError::Rejected(error)),
                _ => Err(HostError::AcceptanceUnknown),
            }
        }
        .await;
        agent.acknowledgements.lock().unwrap().remove(&request_id);
        result
    }
}
