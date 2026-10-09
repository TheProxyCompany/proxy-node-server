//! A Party seat is a direct PH child. Node only holds its routed handle.
use super::*;

#[derive(Clone, Serialize)]
pub(super) struct Launch {
    instance_id: String,
    pid: u32,
    parent_pid: u32,
    parent_generation: u64,
    fork_sha256: String,
}

pub(super) struct Pending {
    command: &'static str,
    child: Weak<Agent>,
    generation: u64,
    sender: oneshot::Sender<Result<Value, String>>,
}

pub(super) fn same_owner(agent: &Agent, owner: Option<&Arc<Agent>>) -> bool {
    match (&agent.owner, owner) {
        (None, None) => true,
        (Some(old), Some(new)) => old.upgrade().is_some_and(|old| Arc::ptr_eq(&old, new)),
        _ => false,
    }
}

pub(super) fn validate_owner(parent: &Agent, spec: &AgentSpec) -> Result<(), HostError> {
    parent.check_active()?;
    let owner = parent.spec.lock().unwrap();
    if parent.owner.is_some()
        || owner.id == spec.id
        || owner.command != spec.command
        || owner.args != spec.args
        || owner.agent_dir != spec.agent_dir
        || owner.state_dir == spec.state_dir
    {
        return Err(HostError::Invalid("Party children require their owning root's executable and identity, and a separate state directory".into()));
    }
    Ok(())
}

pub(super) fn has_busy_children(parent: &Agent) -> bool {
    parent
        .controls
        .lock()
        .unwrap()
        .retain(|_, pending| !pending.sender.is_closed());
    !parent.controls.lock().unwrap().is_empty()
        || parent
            .children
            .lock()
            .unwrap()
            .values()
            .filter_map(Weak::upgrade)
            .any(|child| !child.inputs.lock().unwrap().is_empty())
}

pub(super) fn is_live(child: &Agent) -> bool {
    !child.retired.load(Ordering::SeqCst) && is_attached(child)
}

// A retired child still drains its final receipts before its stop acknowledgement.
fn is_attached(child: &Agent) -> bool {
    let Some(parent) = child.owner.as_ref().and_then(Weak::upgrade) else {
        return false;
    };
    if parent.retired.load(Ordering::SeqCst) {
        return false;
    }
    child
        .child_launch
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|launch| {
            launch.pid != 0
                && launch.parent_pid != 0
                && launch.parent_pid == parent.pid.load(Ordering::SeqCst)
                && launch.parent_generation == parent.generation.load(Ordering::SeqCst)
        })
}

pub(super) fn status(child: &Agent) -> Value {
    let Some(parent) = child.owner.as_ref().and_then(Weak::upgrade) else {
        return Value::Null;
    };
    let parent_id = parent.spec.lock().unwrap().id.clone();
    json!({"parent_id":parent_id,"launch":*child.child_launch.lock().unwrap()})
}

fn invalidate(child: &Agent) {
    *child.child_launch.lock().unwrap() = None;
    child.pid.store(0, Ordering::SeqCst);
    *child.readiness.lock().unwrap() = None;
    *child.state.lock().unwrap() =
        json!({"status":"stopped","pending":child.inputs.lock().unwrap().len()});
    // Dropping senders means unknown acceptance. A lost transport never proves rejection.
    child.acknowledgements.lock().unwrap().clear();
}

pub(super) fn invalidate_children(parent: &Agent) {
    parent.controls.lock().unwrap().clear();
    for child in parent
        .children
        .lock()
        .unwrap()
        .values()
        .filter_map(Weak::upgrade)
    {
        invalidate(&child);
    }
}

pub(super) async fn ensure_started(
    child: &Arc<Agent>,
    parent: &Arc<Agent>,
) -> Result<(), HostError> {
    let _lifecycle = child.process.lock().await;
    child.check_active()?;
    parent.check_active()?;
    if is_live(child) {
        return Ok(());
    }
    let spec = child.spec.lock().unwrap().clone();
    validate_owner(parent, &spec)?;
    let mut seat_config = spec.seat_config.clone();
    seat_config["workspace_mode"] = serde_json::to_value(spec.workspace_mode)?;
    control(
        parent,
        child,
        "party_child_open",
        json!({"spec":{
            "agent_dir":spec.agent_dir,"state_dir":spec.state_dir,"workspace":spec.workspace,
            "workspace_mode":spec.workspace_mode,"seat_config":seat_config,"env":spec.env,
            "space":spec.space,"display_name":spec.display_name
        }}),
    )
    .await?;
    if !is_live(child) {
        return Err(HostError::Stopped);
    }
    Ok(())
}

pub(super) async fn send(child: &Agent, wire: &Value) -> Result<(), HostError> {
    if !matches!(
        wire.get("type").and_then(Value::as_str),
        Some("prompt" | "event" | "observation")
    ) {
        return Err(HostError::Invalid(
            "this operation is not supported on a Party child handle".into(),
        ));
    }
    let _lifecycle = child.process.lock().await;
    if !is_live(child) {
        return Err(HostError::Stopped);
    }
    let parent = child
        .owner
        .as_ref()
        .and_then(Weak::upgrade)
        .ok_or(HostError::Stopped)?;
    let id = child.spec.lock().unwrap().id.clone();
    parent
        .write_direct(&json!({"type":"party_child_send","child_id":id,"input":wire}))
        .await
}

pub(super) async fn abort(child: &Arc<Agent>) -> Result<(), HostError> {
    let _lifecycle = child.process.lock().await;
    if !is_live(child) {
        return Err(HostError::Stopped);
    }
    let parent = child
        .owner
        .as_ref()
        .and_then(Weak::upgrade)
        .ok_or(HostError::Stopped)?;
    control(&parent, child, "party_child_abort", json!({})).await?;
    Ok(())
}

// Caller holds the child's lifecycle lock, including during reconfiguration.
pub(super) async fn stop(child: &Arc<Agent>) -> Result<(), HostError> {
    if !is_attached(child) {
        invalidate(child);
        return Ok(());
    }
    let parent = child
        .owner
        .as_ref()
        .and_then(Weak::upgrade)
        .ok_or(HostError::Stopped)?;
    control(&parent, child, "party_child_stop", json!({})).await?;
    invalidate(child);
    Ok(())
}

async fn control(
    parent: &Arc<Agent>,
    child: &Arc<Agent>,
    command: &'static str,
    mut wire: Value,
) -> Result<Value, HostError> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = format!(
        "node-party-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    );
    wire["type"] = command.into();
    wire["id"] = id.clone().into();
    wire["child_id"] = child.spec.lock().unwrap().id.clone().into();
    let (sender, response) = oneshot::channel();
    parent.controls.lock().unwrap().insert(
        id.clone(),
        Pending {
            command,
            child: Arc::downgrade(child),
            generation: parent.generation.load(Ordering::SeqCst),
            sender,
        },
    );
    let result = if parent.write_direct(&wire).await.is_err() {
        Err(HostError::AcceptanceUnknown)
    } else {
        match tokio::time::timeout(Duration::from_secs(360), response).await {
            Ok(Ok(Ok(reply))) => Ok(reply),
            Ok(Ok(Err(error))) => Err(HostError::Rejected(error)),
            _ => Err(HostError::AcceptanceUnknown),
        }
    };
    parent.controls.lock().unwrap().remove(&id);
    result
}

/// Consume transport envelopes before they reach the root's public journal.
pub(super) fn route(parent: &Agent, event: &Value) -> Result<bool, HostError> {
    if parent.owner.is_some() {
        if event.get("type").and_then(Value::as_str) == Some("host_process_exit") {
            invalidate(parent);
        }
        return Ok(false);
    }
    let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
    if kind == "party_child_event" {
        let child = event
            .get("child_id")
            .and_then(Value::as_str)
            .and_then(|id| {
                parent
                    .children
                    .lock()
                    .unwrap()
                    .get(id)
                    .and_then(Weak::upgrade)
            });
        if let Some(child) = child {
            let current = child.child_launch.lock().unwrap().clone();
            if current.as_ref().is_some_and(|launch| {
                event.get("instance_id").and_then(Value::as_str)
                    == Some(launch.instance_id.as_str())
                    && event.get("pid").and_then(Value::as_u64) == Some(u64::from(launch.pid))
                    && event.get("parent_pid").and_then(Value::as_u64)
                        == Some(u64::from(launch.parent_pid))
                    && is_attached(&child)
            }) {
                if let Some(inner) = event.get("event").filter(|v| v.is_object()) {
                    publish(&child, inner.clone())?;
                }
            }
        }
        return Ok(true);
    }
    let command = event.get("command").and_then(Value::as_str).unwrap_or("");
    if kind != "response"
        || !matches!(
            command,
            "party_child_open" | "party_child_abort" | "party_child_stop" | "party_child_send"
        )
    {
        return Ok(false);
    }
    if command == "party_child_send" {
        // A parent-level refusal carries an ordinary input id, not a control id.
        if event.get("success") == Some(&Value::Bool(false)) {
            let child = event
                .get("child_id")
                .and_then(Value::as_str)
                .and_then(|id| {
                    parent
                        .children
                        .lock()
                        .unwrap()
                        .get(id)
                        .and_then(Weak::upgrade)
                });
            if let Some(child) = child {
                if is_live(&child) {
                    publish(&child, event.clone())?;
                }
            }
        }
        return Ok(true);
    }
    let Some(id) = event.get("id").and_then(Value::as_str) else {
        return Ok(true);
    };
    let pending = {
        let mut controls = parent.controls.lock().unwrap();
        if !controls
            .get(id)
            .is_some_and(|pending| pending.command == command)
        {
            return Ok(true);
        }
        controls.remove(id).unwrap()
    };
    // No child data is logged until its launch identity is validated.
    let result = if pending.generation != parent.generation.load(Ordering::SeqCst) {
        Err("the owning root changed while opening its Party child".into())
    } else if event.get("success") != Some(&Value::Bool(true)) {
        Err(event
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Party child operation failed")
            .into())
    } else if command == "party_child_open" {
        match pending.child.upgrade() {
            Some(child) => install(parent, &child, event, pending.generation)
                .map(|()| event.clone())
                .map_err(|error| error.to_string()),
            None => Err("Party child handle no longer exists".into()),
        }
    } else {
        Ok(event.clone())
    };
    let _ = pending.sender.send(result);
    Ok(true)
}

fn install(parent: &Agent, child: &Agent, reply: &Value, generation: u64) -> Result<(), HostError> {
    let data = &reply["data"];
    let instance_id = data["instance_id"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256);
    let pid = data["pid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v != 0);
    let parent_pid = parent.pid.load(Ordering::SeqCst);
    parent.check_active()?;
    child.check_active()?;
    let fork_sha256 = data["fork_sha256"]
        .as_str()
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()));
    if data["child_id"].as_str() != Some(child.spec.lock().unwrap().id.as_str())
        || data["parent_pid"].as_u64() != Some(u64::from(parent_pid))
        || parent_pid == 0
        || generation != parent.generation.load(Ordering::SeqCst)
        || pid == Some(parent_pid)
        || instance_id.is_none()
        || pid.is_none()
        || fork_sha256.is_none()
    {
        return Err(HostError::Invalid(
            "invalid Party child launch acknowledgement".into(),
        ));
    }
    let launch = Launch {
        instance_id: instance_id.unwrap().into(),
        pid: pid.unwrap(),
        parent_pid,
        parent_generation: generation,
        fork_sha256: fork_sha256.unwrap().into(),
    };
    invalidate(child);
    child.pid.store(launch.pid, Ordering::SeqCst);
    *child.child_launch.lock().unwrap() = Some(launch.clone());
    publish(
        child,
        json!({"type":"host_party_child_started","parent_id":parent.spec.lock().unwrap().id,"launch":launch}),
    )?;
    for (key, kind) in [("runtime", "root_state"), ("readiness", "root_readiness")] {
        if let Some(snapshot) = data
            .get(key)
            .filter(|v| v.get("type").and_then(Value::as_str) == Some(kind))
        {
            publish(child, snapshot.clone())?;
        }
    }
    Ok(())
}
