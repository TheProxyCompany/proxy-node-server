//! Context preparation is a creator relationship. Node owns each instance's process and address.
use super::*;

pub(super) struct Pending {
    generation: u64,
    sender: oneshot::Sender<Result<Value, String>>,
}

pub(super) fn same_creator(agent: &Agent, creator: Option<&str>) -> bool {
    agent.creator.as_deref() == creator
}

pub(super) fn validate_creator(parent: &Agent, spec: &AgentSpec) -> Result<(), HostError> {
    parent.check_active()?;
    let creator = parent.spec.lock().unwrap();
    if parent.creator.is_some()
        || creator.id == spec.id
        || creator.command != spec.command
        || creator.args != spec.args
        || creator.agent_dir != spec.agent_dir
        || creator.state_dir == spec.state_dir
    {
        return Err(HostError::Invalid("Party instances require their creator's executable and identity and a separate state directory".into()));
    }
    Ok(())
}

pub(super) async fn prepare(child: &Arc<Agent>, parent: &Arc<Agent>) -> Result<(), HostError> {
    let _lifecycle = child.process.lock().await;
    let spec = child.spec.lock().unwrap().clone();
    if spec.state_dir.join("fork.json").is_file() {
        return Ok(());
    }
    validate_creator(parent, &spec)?;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = format!(
        "node-fork-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    );
    let mut seat = spec.seat_config.clone();
    seat["workspace_mode"] = serde_json::to_value(spec.workspace_mode)?;
    let wire = json!({"type":"party_child_open","id":id,"child_id":spec.id,"spec":{
        "agent_dir":spec.agent_dir,"state_dir":spec.state_dir,"workspace":spec.workspace,
        "workspace_mode":spec.workspace_mode,"seat_config":seat,"env":spec.env,
        "space":spec.space,"display_name":spec.display_name
    }});
    let (sender, response) = oneshot::channel();
    parent.controls.lock().unwrap().insert(
        id.clone(),
        Pending {
            generation: parent.generation.load(Ordering::SeqCst),
            sender,
        },
    );
    let result = if parent.write_direct(&wire).await.is_err() {
        Err(HostError::AcceptanceUnknown)
    } else {
        match tokio::time::timeout(Duration::from_secs(360), response).await {
            Ok(Ok(Ok(_))) => Ok(()),
            Ok(Ok(Err(error))) => Err(HostError::Rejected(error)),
            _ => Err(HostError::AcceptanceUnknown),
        }
    };
    parent.controls.lock().unwrap().remove(&id);
    result?;
    if !spec.state_dir.join("fork.json").is_file() {
        return Err(HostError::Invalid(
            "creator did not persist the instance context".into(),
        ));
    }
    Ok(())
}

pub(super) fn route(parent: &Agent, event: &Value) -> Result<bool, HostError> {
    if event["type"] != "response" || event["command"] != "party_child_open" {
        return Ok(false);
    }
    let Some(id) = event["id"].as_str() else {
        return Ok(true);
    };
    let Some(pending) = parent.controls.lock().unwrap().remove(id) else {
        return Ok(true);
    };
    let result = if pending.generation != parent.generation.load(Ordering::SeqCst) {
        Err("creator restarted while preparing context".into())
    } else if event["success"] != true {
        Err(event["error"]
            .as_str()
            .unwrap_or("instance preparation failed")
            .into())
    } else {
        Ok(event.clone())
    };
    let _ = pending.sender.send(result);
    Ok(true)
}
