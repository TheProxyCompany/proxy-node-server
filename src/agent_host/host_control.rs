//! Private runtime requests use the existing host registry and never enter its event log.
use super::*;

#[derive(Deserialize)]
struct Spawn {
    instance_id: String,
    identity: PathBuf,
    state: PathBuf,
    workspace: PathBuf,
    workspace_mode: WorkspaceMode,
    seat: Value,
    #[serde(default)]
    env: BTreeMap<String, String>,
    space: Option<SpaceBinding>,
    initial_input: AgentInput,
    timeout_seconds: Option<f64>,
}

struct Pending(Arc<Agent>);

impl Drop for Pending {
    fn drop(&mut self) {
        self.0.host_controls.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) fn route(host: &AgentHost, caller: &Arc<Agent>, generation: u64, event: &Value) -> bool {
    if event["type"] != "host_control" {
        return false;
    }
    let mut tasks = host.control_tasks.lock().unwrap();
    if host.closing.load(Ordering::SeqCst) {
        return true;
    }
    tasks.retain(|task| !task.is_finished());
    let host = host.clone();
    let caller = Arc::clone(caller);
    caller.host_controls.fetch_add(1, Ordering::SeqCst);
    let pending = Pending(Arc::clone(&caller));
    let request = event.clone();
    // Spawn admission waits for another runtime's fsynced ACK. Keep draining
    // this caller's pipe while that runtime starts or makes its own requests.
    tasks.push(tokio::spawn(async move {
        let _pending = pending;
        let Some(id) = request["id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 256)
        else {
            return;
        };
        let result = handle(&host, &caller, generation, &request).await;
        let reply = match result {
            Ok(result) => json!({"type":"host_control_result","id":id,"ok":true,"result":result}),
            Err(error) => {
                json!({"type":"host_control_result","id":id,"ok":false,"error":public_error(&error),"error_code":error_code(&error)})
            }
        };
        if caller.generation.load(Ordering::SeqCst) == generation {
            let _ = caller.write_direct(&reply).await;
        }
    }));
    true
}

fn error_code(error: &HostError) -> &'static str {
    match error {
        HostError::Forbidden => "denied",
        HostError::NotFound(_) => "not_found",
        HostError::Busy => "busy",
        HostError::AcceptanceUnknown => "acceptance_unknown",
        HostError::Stopped => "stopped",
        HostError::Invalid(_) | HostError::Json(_) => "invalid",
        _ => "failure",
    }
}

fn public_error(error: &HostError) -> &'static str {
    match error {
        HostError::Forbidden => "host control access denied",
        HostError::NotFound(_) => "hosted instance not found",
        HostError::Busy => "hosted instance is busy",
        HostError::AcceptanceUnknown => "runtime acceptance is unknown; retry the same input id",
        HostError::Stopped => "agent host or runtime stopped",
        HostError::Invalid(_) | HostError::Json(_) => "invalid host control request",
        _ => "agent host could not complete the request",
    }
}

fn child_spec(caller: &AgentSpec, child: &Spawn) -> Result<AgentSpec, HostError> {
    if !valid_id(&child.instance_id) || child.instance_id == caller.id || !child.seat.is_object() {
        return Err(HostError::Invalid(
            "a distinct instance id and seat are required".into(),
        ));
    }
    let parent_state = caller.state_dir.canonicalize()?;
    let folder = parent_state
        .join("children")
        .join(&child.instance_id)
        .canonicalize()?;
    let identity = child.identity.canonicalize()?;
    let state = child.state.canonicalize()?;
    if !folder.starts_with(&parent_state)
        || identity != folder.join("identity")
        || state != folder.join("state")
        || !state.join("fork.json").is_file()
    {
        return Err(HostError::Invalid(
            "a child requires its own prepared identity and state".into(),
        ));
    }
    if caller.workspace_mode == WorkspaceMode::Guest && child.workspace_mode != WorkspaceMode::Guest
    {
        return Err(HostError::Forbidden);
    }
    let new_space = child.space.as_ref().is_some_and(|space| {
        caller
            .space
            .as_ref()
            .is_none_or(|parent| parent.space_id != space.space_id)
    });
    if caller.space.is_some() && !new_space {
        return Err(HostError::Invalid(
            "a computer child requires a distinct Space".into(),
        ));
    }
    let workspace = child.workspace.canonicalize()?;
    match child.workspace_mode {
        WorkspaceMode::Host if workspace != folder.join("workspace") => {
            return Err(HostError::Forbidden);
        }
        WorkspaceMode::Guest
            if workspace != caller.workspace.canonicalize()?
                && !child.space.as_ref().is_some_and(|space| {
                    space.workspace_root.canonicalize().ok().as_ref() == Some(&workspace)
                }) =>
        {
            return Err(HostError::Forbidden);
        }
        _ => {}
    }
    let mut seat = child.seat.clone();
    if !seat["builtins"].is_array() {
        return Err(HostError::Forbidden);
    }
    for key in ["builtins", "allowed"] {
        let parent = caller.seat_config[key].as_array();
        if seat[key].as_array().is_some_and(|tools| {
            tools.iter().any(|tool| {
                !tool.is_string() || !parent.is_some_and(|parent| parent.contains(tool))
            })
        }) {
            return Err(HostError::Forbidden);
        }
        if !seat[key].is_null() && !seat[key].is_array() {
            return Err(HostError::Forbidden);
        }
    }
    if let Some(servers) = seat["mcpServers"].as_object() {
        for (name, config) in servers {
            let parent = &caller.seat_config["mcpServers"][name];
            if config != parent
                && !(new_space
                    && parent["requires_space"] == true
                    && config["requires_space"] == true)
            {
                return Err(HostError::Forbidden);
            }
        }
    } else if !seat["mcpServers"].is_null() {
        return Err(HostError::Forbidden);
    }
    if seat["allowed"].is_null() {
        seat["allowed"] = json!([]);
    }
    if seat["mcpServers"].is_null() {
        seat["mcpServers"] = json!({});
    }
    for key in [
        "agent_id",
        "conversation_id",
        "participant_id",
        "disallowed",
    ] {
        seat[key] = caller.seat_config[key].clone();
    }
    if seat["agent_id"].is_null() {
        seat["agent_id"] = caller.id.clone().into();
    }
    seat["instance_id"] = child.instance_id.clone().into();
    seat["creator_id"] = caller.id.clone().into();
    let mut env = caller.env.clone();
    env.extend(child.env.clone());
    env.insert("PROXY_HARNESS_HOST_CONTROL".into(), "1".into());
    env.remove("PROXY_HARNESS_WORKER");
    env.remove("PROXY_AGENT_WORKER");
    Ok(AgentSpec {
        id: child.instance_id.clone(),
        display_name: None,
        command: caller.command.clone(),
        args: caller.args.clone(),
        agent_dir: identity,
        state_dir: state,
        workspace,
        workspace_mode: child.workspace_mode,
        seat_config: seat,
        env,
        space: child.space.clone(),
    })
}

fn descendant(host: &AgentHost, caller: &str, id: &str) -> Result<Arc<Agent>, HostError> {
    let target = host.agent(id)?;
    let mut creator = target.creator.clone();
    while let Some(parent) = creator {
        if parent == caller {
            target.check_active()?;
            return Ok(target);
        }
        creator = host.agent(&parent)?.creator.clone();
    }
    Err(HostError::Forbidden)
}

fn granted(spec: &AgentSpec, op: &str) -> bool {
    let name = match op {
        "spawn" => "spawn_agent",
        "status" => "agent_status",
        "send" => "agent_send",
        "cancel" => "agent_cancel",
        _ => return false,
    };
    spec.env
        .get("PROXY_HARNESS_HOST_CONTROL")
        .is_some_and(|value| value == "1")
        && spec.seat_config["builtins"]
            .as_array()
            .is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool == name || (op == "status" && tool == "spawn_agent"))
            })
}

async fn status(host: &AgentHost, id: &str) -> Result<Value, HostError> {
    use std::io::Read;
    let mut status = host.status(id).await?;
    let agent = host.agent(id)?;
    let _log = agent.log.lock().unwrap();
    let mut file = File::open(&agent.log_path)?;
    let offset = file.metadata()?.len().saturating_sub(30 * 1024);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let start = if offset == 0 {
        0
    } else {
        bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |at| at + 1)
    };
    status["stdout"] = String::from_utf8_lossy(&bytes[start..]).into_owned().into();
    Ok(status)
}

async fn cancel(host: &AgentHost, id: &str, timed_out: bool) -> Result<(), HostError> {
    let mut children = host.registered_agents();
    children.retain(|child| descendant(host, id, child).is_ok());
    // Every child is independently owned, so stopping a creator does not stop
    // its descendants. Visit every registered descendant on explicit cancel.
    let mut result = Ok(());
    for child in children.into_iter().chain(std::iter::once(id.to_owned())) {
        let agent = host.agent(&child)?;
        if child != id || !timed_out {
            if let Some(timer) = agent.deadline.lock().unwrap().take() {
                timer.abort();
            }
        }
        let stopped = host.stop(&child).await;
        let cleanup_confirmed = stopped.is_ok();
        if let Err(error) = stopped {
            result = Err(error);
        }
        let event = if timed_out {
            "host_deadline_expired"
        } else {
            "host_cancelled"
        };
        publish(
            &agent,
            json!({"type":event,"cleanup_confirmed":cleanup_confirmed}),
        )?;
    }
    result
}

pub(super) fn resume_deadline(host: &AgentHost, agent: &Arc<Agent>) {
    let log = agent.log.lock().unwrap();
    let Some(at) = log
        .deadline_at
        .filter(|_| !log.deadline_expired && log.stop_reason.is_none())
    else {
        return;
    };
    drop(log);
    let mut task = agent.deadline.lock().unwrap();
    if task.is_some() {
        return;
    }
    let host = host.clone();
    let agent = Arc::clone(agent);
    let timer = tokio::spawn(async move {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        tokio::time::sleep(Duration::from_millis(at.saturating_sub(now))).await;
        let id = agent.spec.lock().unwrap().id.clone();
        let _ = cancel(&host, &id, true).await;
    });
    *task = Some(timer.abort_handle());
}

fn deadline_at(timeout: Option<f64>) -> Result<Option<u64>, HostError> {
    let Some(timeout) = timeout else {
        return Ok(None);
    };
    let duration = Duration::try_from_secs_f64(timeout)
        .map_err(|_| HostError::Invalid("timeout_seconds must be finite and positive".into()))?;
    if duration.is_zero() {
        return Err(HostError::Invalid(
            "timeout_seconds must be finite and positive".into(),
        ));
    }
    let at = std::time::SystemTime::now()
        .checked_add(duration)
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|at| u64::try_from(at.as_millis()).ok())
        .ok_or_else(|| HostError::Invalid("timeout_seconds is out of range".into()))?;
    Ok(Some(at))
}

async fn deadline(host: &AgentHost, id: &str, at: Option<u64>) -> Result<(), HostError> {
    let agent = host.agent(id)?;
    // Serialize with registration and other admissions so a retry cannot
    // extend a deadline already written to this instance's existing log.
    let _admission = agent.submission.lock().await;
    if !agent.log.lock().unwrap().deadline_configured {
        publish(&agent, json!({"type":"host_deadline","deadline_at":at}))?;
    }
    resume_deadline(host, &agent);
    Ok(())
}

async fn handle(
    host: &AgentHost,
    caller: &Arc<Agent>,
    generation: u64,
    request: &Value,
) -> Result<Value, HostError> {
    caller.check_active()?;
    if caller.generation.load(Ordering::SeqCst) != generation {
        return Err(HostError::Stopped);
    }
    let caller_spec = caller.spec.lock().unwrap().clone();
    if !granted(&caller_spec, request["op"].as_str().unwrap_or_default()) {
        return Err(HostError::Forbidden);
    }
    if request["op"] == "spawn" {
        let child: Spawn = serde_json::from_value(request.clone())?;
        let at = deadline_at(child.timeout_seconds)?;
        let spec = child_spec(&caller_spec, &child)?;
        host.register_instance(spec, Some(caller_spec.id)).await?;
        deadline(host, &child.instance_id, at).await?;
        if host
            .agent(&child.instance_id)?
            .log
            .lock()
            .unwrap()
            .stop_reason
            .is_some()
        {
            return status(host, &child.instance_id).await;
        }
        let accepted = host.submit(&child.instance_id, child.initial_input).await?;
        let mut status = status(host, &child.instance_id).await?;
        status["accepted"] = accepted;
        return Ok(status);
    }
    let id = request["instance_id"]
        .as_str()
        .ok_or_else(|| HostError::Invalid("instance_id is required".into()))?;
    descendant(host, &caller_spec.id, id)?;
    match request["op"].as_str() {
        Some("status") => status(host, id).await,
        Some("send") => {
            let input = serde_json::from_value(request["input"].clone())?;
            host.submit(id, input).await
        }
        Some("cancel") => {
            cancel(host, id, false).await?;
            status(host, id).await
        }
        _ => Err(HostError::Invalid("unknown host control operation".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(root: &Path, id: &str) -> AgentSpec {
        AgentSpec {
            id: id.into(),
            display_name: None,
            command: "/bin/false".into(),
            args: vec![],
            agent_dir: root.join(id).join("identity"),
            state_dir: root.join(id).join("state"),
            workspace: root.into(),
            workspace_mode: WorkspaceMode::Host,
            seat_config: json!({"agent_id":"owner","conversation_id":"conversation","participant_id":"seat","builtins":["spawn_agent","agent_status","agent_send","agent_cancel"],"mcpServers":{"server":{"headers":{"Authorization":"private-header"}}}}),
            env: BTreeMap::from([
                ("PROXY_HARNESS_HOST_CONTROL".into(), "1".into()),
                ("PROXY_HARNESS_API_KEY".into(), "private-key".into()),
            ]),
            space: None,
        }
    }

    #[test]
    fn prepared_children_cannot_change_paths_workspace_or_tool_authority() {
        let root = tempfile::tempdir().unwrap();
        let parent = spec(root.path(), "parent");
        let folder = parent.state_dir.join("children/child");
        for name in ["identity", "state", "workspace"] {
            std::fs::create_dir_all(folder.join(name)).unwrap();
        }
        std::fs::write(folder.join("state/fork.json"), "{}").unwrap();
        let mut child: Spawn = serde_json::from_value(json!({
            "instance_id":"child","identity":folder.join("identity"),
            "state":folder.join("state"),"workspace":folder.join("workspace"),
            "workspace_mode":"host","seat":parent.seat_config,
            "env":{"PROXY_HARNESS_WORKER":"1","PROXY_HARNESS_HOST_CONTROL":"0"},
            "initial_input":{"id":"initial","message":"task"}
        }))
        .unwrap();
        child.seat["agent_id"] = json!("another-owner");
        let registered = child_spec(&parent, &child).unwrap();
        assert_eq!(registered.seat_config["agent_id"], "owner");
        assert_eq!(registered.env["PROXY_HARNESS_HOST_CONTROL"], "1");
        assert!(!registered.env.contains_key("PROXY_HARNESS_WORKER"));
        child.seat["builtins"] = json!(["ungranted_tool"]);
        assert!(matches!(
            child_spec(&parent, &child),
            Err(HostError::Forbidden)
        ));
        child.seat = parent.seat_config.clone();
        child.seat["mcpServers"]["server"]["url"] = json!("https://another-recipient.example");
        assert!(matches!(
            child_spec(&parent, &child),
            Err(HostError::Forbidden)
        ));
        child.seat = parent.seat_config.clone();
        let mut guest = parent.clone();
        guest.workspace_mode = WorkspaceMode::Guest;
        assert!(matches!(
            child_spec(&guest, &child),
            Err(HostError::Forbidden)
        ));
        child.workspace = root.path().into();
        assert!(matches!(
            child_spec(&parent, &child),
            Err(HostError::Forbidden)
        ));
        child.workspace = folder.join("workspace");
        child.identity = parent.state_dir.clone();
        assert!(matches!(
            child_spec(&parent, &child),
            Err(HostError::Invalid(_))
        ));
        let malformed = serde_json::from_value::<Spawn>(json!({"instance_id":"private-value"}))
            .err()
            .unwrap();
        assert!(!public_error(&HostError::Json(malformed)).contains("private-value"));
    }

    #[tokio::test]
    async fn shutdown_fences_pending_private_admissions_and_reconfiguration() {
        let root = tempfile::tempdir().unwrap();
        let host = AgentHost::open(root.path().join("host")).unwrap();
        let mut config = spec(root.path(), "parent");
        host.register(config.clone()).await.unwrap();
        let caller = host.agent("parent").unwrap();
        // A valid correlation waits on a private reply pipe without starting a runtime.
        assert!(route(
            &host,
            &caller,
            0,
            &json!({"type":"host_control","id":"pending","op":"status","instance_id":"missing"})
        ));
        config.seat_config["model"] = json!("changed");
        assert!(matches!(
            host.register(config.clone()).await,
            Err(HostError::Busy)
        ));
        host.shutdown().await;
        assert_eq!(caller.host_controls.load(Ordering::SeqCst), 0);
        assert!(host.control_tasks.lock().unwrap().is_empty());
        assert!(matches!(
            host.register(config).await,
            Err(HostError::Stopped)
        ));
        assert!(route(
            &host,
            &caller,
            0,
            &json!({"type":"host_control","id":"after-shutdown"})
        ));
        assert!(host.control_tasks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn private_controls_require_capability_grants_and_creator_ancestry() {
        let root = tempfile::tempdir().unwrap();
        let host = AgentHost::open(root.path().join("host")).unwrap();
        for (id, creator) in [
            ("parent", None),
            ("other", None),
            ("child", Some("parent")),
            ("grandchild", Some("child")),
        ] {
            host.register_instance(spec(root.path(), id), creator.map(str::to_owned))
                .await
                .unwrap();
        }
        let caller = host.agent("parent").unwrap();
        let status = json!({"op":"status","instance_id":"grandchild"});
        assert_eq!(
            handle(&host, &caller, 0, &status).await.unwrap()["agent_id"],
            "grandchild"
        );
        let other = host.agent("other").unwrap();
        assert!(matches!(
            handle(&host, &other, 0, &status).await,
            Err(HostError::Forbidden)
        ));
        caller
            .spec
            .lock()
            .unwrap()
            .env
            .remove("PROXY_HARNESS_HOST_CONTROL");
        assert!(matches!(
            handle(&host, &caller, 0, &status).await,
            Err(HostError::Forbidden)
        ));
        caller
            .spec
            .lock()
            .unwrap()
            .env
            .insert("PROXY_HARNESS_HOST_CONTROL".into(), "1".into());
        caller.spec.lock().unwrap().seat_config["builtins"] = json!(["spawn_agent"]);
        assert_eq!(
            handle(&host, &caller, 0, &status).await.unwrap()["agent_id"],
            "grandchild"
        );
        caller.spec.lock().unwrap().seat_config["builtins"] = json!([]);
        assert!(matches!(
            handle(&host, &caller, 0, &status).await,
            Err(HostError::Forbidden)
        ));
        assert!(route(
            &host,
            &caller,
            0,
            &json!({"type":"host_control","env":{"SECRET":"private-frame"}})
        ));
        tokio::task::yield_now().await;
        let grandchild = host.agent("grandchild").unwrap();
        for index in 0..64 {
            publish(
                &grandchild,
                json!({"type":"message_update","text":"x".repeat(1024),"index":index}),
            )
            .unwrap();
        }
        let output = super::status(&host, "grandchild").await.unwrap()["stdout"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(output.len() <= 30 * 1024);
        assert!(output.contains("\"index\":63"));
        assert!(!output.contains("\"index\":0,"));
        let descriptor = serde_json::to_string(&host.descriptor("grandchild").unwrap()).unwrap();
        assert!(descriptor.contains("owner"));
        for id in host.registered_agents() {
            let log = std::fs::read_to_string(host.agent(&id).unwrap().log_path.clone()).unwrap();
            for secret in ["private-key", "private-header", "private-frame"] {
                assert!(!log.contains(secret));
                assert!(!descriptor.contains(secret));
            }
        }
        host.shutdown().await;
    }

    #[tokio::test]
    async fn deadlines_and_cancellation_survive_reopen_without_losing_admitted_work() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("host");
        let config = spec(root.path(), "child");
        let host = AgentHost::open(&path).unwrap();
        host.register_instance(config.clone(), Some("parent".into()))
            .await
            .unwrap();
        let child = host.agent("child").unwrap();
        child
            .inputs
            .lock()
            .unwrap()
            .insert("accepted-before-timeout".into());
        let at = deadline_at(Some(0.01)).unwrap();
        deadline(&host, "child", at).await.unwrap();
        deadline(&host, "child", deadline_at(Some(60.0)).unwrap())
            .await
            .unwrap();
        assert_eq!(child.log.lock().unwrap().deadline_at, at);
        tokio::time::timeout(Duration::from_secs(2), async {
            while host.status("child").await.unwrap()["runtime"]["status"] != "timed_out" {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            child
                .inputs
                .lock()
                .unwrap()
                .contains("accepted-before-timeout")
        );
        host.shutdown().await;
        drop(child);
        drop(host);
        tokio::task::yield_now().await;
        let host = AgentHost::open(&path).unwrap();
        host.register_instance(config, Some("parent".into()))
            .await
            .unwrap();
        assert_eq!(
            host.status("child").await.unwrap()["runtime"]["status"],
            "timed_out"
        );
        assert_eq!(
            host.agent("child").unwrap().log.lock().unwrap().deadline_at,
            at
        );
        host.register(spec(root.path(), "unbounded")).await.unwrap();
        deadline(&host, "unbounded", None).await.unwrap();
        deadline(&host, "unbounded", deadline_at(Some(0.01)).unwrap())
            .await
            .unwrap();
        assert!(
            host.agent("unbounded")
                .unwrap()
                .log
                .lock()
                .unwrap()
                .deadline_at
                .is_none()
        );
        cancel(&host, "unbounded", false).await.unwrap();
        assert_eq!(
            host.status("unbounded").await.unwrap()["runtime"]["status"],
            "cancelled"
        );
        assert!(deadline_at(Some(f64::NAN)).is_err());
        assert!(deadline_at(Some(-1.0)).is_err());
        assert!(deadline_at(Some(0.0)).is_err());
        host.shutdown().await;
    }
}
