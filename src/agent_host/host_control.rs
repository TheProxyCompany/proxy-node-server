//! Private runtime requests use the existing host registry and never enter its event log.
use super::*;

#[derive(Deserialize)]
struct Spawn {
    instance_id: String,
    identity: PathBuf,
    state: PathBuf,
    workspace: Option<PathBuf>,
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
        HostError::Rejected(_) => "rejected",
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
        HostError::Rejected(_) => {
            "runtime rejected this input; inspect its retained result before retrying"
        }
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
    let workspace = match child.workspace_mode {
        WorkspaceMode::Host => child
            .workspace
            .as_ref()
            .ok_or(HostError::Forbidden)?
            .canonicalize()?,
        WorkspaceMode::Guest => {
            if let Some(workspace) = &child.workspace {
                if !workspace.is_absolute()
                    || workspace
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                {
                    return Err(HostError::Forbidden);
                }
                workspace.clone()
            } else {
                if child
                    .space
                    .as_ref()
                    .is_none_or(|space| space.workspace_root.is_some())
                {
                    return Err(HostError::Forbidden);
                }
                // The RPC process still needs a local working directory. It is
                // never passed to the guest as a workspace or tool authority.
                state.clone()
            }
        }
    };
    match child.workspace_mode {
        WorkspaceMode::Host if workspace != folder.join("workspace") => {
            return Err(HostError::Forbidden);
        }
        WorkspaceMode::Guest
            if child.workspace.is_some()
                && workspace != caller.workspace
                && !child
                    .space
                    .as_ref()
                    .is_some_and(|space| space.workspace_root.as_ref() == Some(&workspace)) =>
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
    if caller.seat_config["task_id"].is_null()
        && seat["habit_id"].as_str().is_some_and(|id| !id.is_empty())
    {
        env.insert("PROXY_HARNESS_WORKER".into(), "1".into());
    } else {
        env.remove("PROXY_HARNESS_WORKER");
        seat.as_object_mut()
            .expect("validated seat")
            .remove("habit_id");
    }
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
        "spawn" | "restore" => "spawn_agent",
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

fn admitted_instance(host: &AgentHost, caller: &str, child: &Spawn) -> Result<(), HostError> {
    let mut registered = false;
    let mut accepted = false;
    let mut reader = BufReader::new(File::open(
        host.root.join(&child.instance_id).join("events.jsonl"),
    )?);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || !line.ends_with('\n') {
            break;
        }
        let record: HostEvent = serde_json::from_str(&line)?;
        if record.agent_id != child.instance_id {
            return Err(HostError::Forbidden);
        }
        if record.event["type"] == "host_retired" {
            return Err(HostError::Forbidden);
        }
        if record.event["type"] == "host_instance_registered" {
            if record.event["creator_id"].as_str() != Some(caller) {
                return Err(HostError::Forbidden);
            }
            registered = true;
        }
        if record.event["type"] == "accepted"
            && record.event["durable"] == true
            && record.event["id"] == child.initial_input.id
        {
            accepted = true;
        }
    }
    if !registered || !accepted {
        return Err(HostError::Invalid(
            "restoration requires prior durable input acceptance".into(),
        ));
    }
    let initial = serde_json::to_value(&child.initial_input)?;
    let mut reader = BufReader::new(File::open(child.state.join("inbox.jsonl"))?);
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || !line.ends_with('\n') {
            break;
        }
        let record: Value = serde_json::from_str(&line)?;
        if record["kind"] == "input" && record["input"]["id"] == child.initial_input.id {
            if initial
                .as_object()
                .unwrap()
                .iter()
                .any(|(key, value)| record["input"][key] != *value)
            {
                return Err(HostError::Forbidden);
            }
            let journal = File::open(child.state.join("log.jsonl"))?;
            if host.agent(&child.instance_id).is_err() {
                fs2::FileExt::try_lock_exclusive(&journal).map_err(|_| HostError::Busy)?;
            }
            return Ok(());
        }
    }
    Err(HostError::Invalid(
        "the admitted child inbox is unavailable".into(),
    ))
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

pub(super) async fn cancel(host: &AgentHost, id: &str, timed_out: bool) -> Result<(), HostError> {
    // Creator identity is a relationship, not ownership of another instance's lifetime.
    let agent = host.agent(id)?;
    if !timed_out {
        if let Some(timer) = agent.deadline.lock().unwrap().take() {
            timer.abort();
        }
    }
    let stopped = host.cancel_instance(id).await;
    let event = if timed_out {
        "host_deadline_expired"
    } else {
        "host_cancelled"
    };
    publish(
        &agent,
        json!({"type":event,"cleanup_confirmed":stopped.is_ok()}),
    )?;
    stopped
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
    if host.closing.load(Ordering::SeqCst)
        && !matches!(request["op"].as_str(), Some("status" | "cancel"))
    {
        return Err(HostError::Stopped);
    }
    let caller_spec = caller.spec.lock().unwrap().clone();
    if caller.is_restoring() && !matches!(request["op"].as_str(), Some("restore" | "status")) {
        return Err(HostError::Forbidden);
    }
    if !granted(&caller_spec, request["op"].as_str().unwrap_or_default()) {
        return Err(HostError::Forbidden);
    }
    if matches!(request["op"].as_str(), Some("spawn" | "restore")) {
        let child: Spawn = serde_json::from_value(request.clone())?;
        let at = deadline_at(child.timeout_seconds)?;
        let spec = child_spec(&caller_spec, &child)?;
        let restoring = request["op"] == "restore";
        if restoring {
            admitted_instance(host, &caller_spec.id, &child)?;
        }
        host.register_instance(spec, Some(caller_spec.id)).await?;
        if !restoring {
            deadline(host, &child.instance_id, at).await?;
        }
        if host
            .agent(&child.instance_id)?
            .log
            .lock()
            .unwrap()
            .stop_reason
            .is_some()
        {
            if restoring {
                host.restore_descendants(&child.instance_id).await?;
            }
            return status(host, &child.instance_id).await;
        }
        if restoring {
            let expired = host
                .agent(&child.instance_id)?
                .log
                .lock()
                .unwrap()
                .deadline_passed();
            if expired {
                host.restore_descendants(&child.instance_id).await?;
                return status(host, &child.instance_id).await;
            }
            host.ensure_started(&child.instance_id).await?;
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
    if request["op"] == "status" && matches!(host.agent(id), Err(HostError::NotFound(_))) {
        let mut recorded = host
            .recorded_status(id)?
            .ok_or_else(|| HostError::NotFound(id.into()))?;
        if recorded["creator_id"].as_str() != Some(&caller_spec.id) {
            return Err(HostError::Forbidden);
        }
        recorded["pid"] = Value::Null;
        recorded["hosted"] = json!(false);
        return Ok(recorded);
    }
    let related = descendant(host, &caller_spec.id, id).is_ok();
    let descriptor = host.descriptor(id)?;
    let same_conversation = caller_spec.seat_config["conversation_id"]
        .as_str()
        .filter(|conversation| !conversation.is_empty())
        .is_some_and(|conversation| descriptor.conversation_id.as_deref() == Some(conversation));
    if !related && !(request["op"] == "send" && same_conversation) {
        return Err(HostError::Forbidden);
    }
    match request["op"].as_str() {
        Some("status") => status(host, id).await,
        Some("send") => {
            let mut input: AgentInput = serde_json::from_value(request["input"].clone())?;
            input.conversation_id = descriptor.conversation_id;
            input.participant_id = descriptor.participant_id;
            input.task_id = descriptor.task_id;
            input.source = Some("agent".into());
            let mut data = input.data.take().unwrap_or_else(|| json!({}));
            if !data.is_object() {
                data = json!({"payload":data});
            }
            data["sender_instance_id"] = caller_spec.id.clone().into();
            data["sender_agent_id"] = caller_spec.seat_config["agent_id"]
                .as_str()
                .unwrap_or(&caller_spec.id)
                .into();
            input.data = Some(data);
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

    #[tokio::test]
    async fn recorded_status_reads_admission_creator_and_terminal_state_without_repair_or_registration()
     {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host");
        let host = AgentHost::open(&path).unwrap();
        host.register_instance(spec(directory.path(), "child"), Some("creator".into()))
            .await
            .unwrap();
        let child = host.agent("child").unwrap();
        publish(
            &child,
            json!({"type":"accepted","id":"original","durable":true}),
        )
        .unwrap();
        publish(
            &child,
            json!({"type":"host_cancelled","cleanup_confirmed":true}),
        )
        .unwrap();
        host.shutdown().await;
        drop(child);
        drop(host);
        let journal = path.join("child/events.jsonl");
        OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(b"{\"incomplete\":")
            .unwrap();
        let before = std::fs::read(&journal).unwrap();
        let reopened = AgentHost::open(&path).unwrap();
        let recorded = reopened.recorded_status("child").unwrap().unwrap();
        assert_eq!(recorded["creator_id"], "creator");
        assert_eq!(recorded["admitted"], true);
        assert_eq!(recorded["runtime"]["status"], "cancelled");
        assert_eq!(recorded["runtime"]["cleanup_confirmed"], true);
        assert_eq!(recorded["retired"], false);
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert!(reopened.registered_agents().is_empty());
        assert!(
            reopened
                .recorded_status("never-admitted")
                .unwrap()
                .is_none()
        );
        assert!(!path.join("never-admitted").exists());
        assert!(
            reopened
                .register_instance(
                    spec(directory.path(), "child"),
                    Some("different-creator".into())
                )
                .await
                .is_err()
        );
        assert!(reopened.registered_agents().is_empty());
        reopened.shutdown().await;
    }

    #[tokio::test]
    async fn restoration_only_keeps_terminal_state_and_refuses_inputs_without_its_ack() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host");
        let host = AgentHost::open(&path).unwrap();
        let mut config = spec(directory.path(), "creator");
        std::fs::create_dir_all(&config.state_dir).unwrap();
        config.command = "/usr/bin/python3".into();
        config.args = vec!["-c".into(), r#"
import json, pathlib, sys, time
assert '--restore-instances-only' in sys.argv
state = pathlib.Path(sys.argv[sys.argv.index('--state') + 1])
with (state / 'restoration-starts').open('a') as f: f.write('started\n')
(state / 'ready').touch()
while not (state / 'release').exists(): time.sleep(0.01)
print(json.dumps({'type':'host_restoration_complete','success':True,'restored':[],'refused':[]}), flush=True)
"#.into()];
        host.register(config.clone()).await.unwrap();
        let agent = host.agent("creator").unwrap();
        publish(
            &agent,
            json!({"type":"host_cancelled","cleanup_confirmed":true}),
        )
        .unwrap();
        let restoring_host = host.clone();
        let restoring =
            tokio::spawn(async move { restoring_host.restore_descendants("creator").await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !config.state_dir.join("ready").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let status = host.status("creator").await.unwrap();
        assert_eq!(status["pid"], Value::Null);
        assert_eq!(status["hosted"], false);
        assert_eq!(status["runtime"]["status"], "cancelled");
        assert_eq!(status["runtime"]["cleanup_confirmed"], true);
        let input: AgentInput =
            serde_json::from_value(json!({"id":"must-not-run","message":"must-not-run"})).unwrap();
        assert!(matches!(
            host.submit("creator", input).await,
            Err(HostError::Busy)
        ));
        assert!(matches!(
            handle(
                &host,
                &agent,
                agent.generation.load(Ordering::SeqCst),
                &json!({"op":"spawn"})
            )
            .await,
            Err(HostError::Forbidden)
        ));
        std::fs::write(config.state_dir.join("release"), "").unwrap();
        let result = restoring.await.unwrap().unwrap();
        assert_eq!(result["type"], "host_restoration_complete");
        assert_eq!(host.restore_descendants("creator").await.unwrap(), result);
        assert_eq!(
            std::fs::read_to_string(config.state_dir.join("restoration-starts"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(
            host.status("creator").await.unwrap()["runtime"]["status"],
            "cancelled"
        );
        let log = std::fs::read_to_string(&agent.log_path).unwrap();
        assert!(!log.contains("host_resumed"));
        assert!(!log.contains("must-not-run"));
        for (id, output) in [
            ("missing", ""),
            (
                "ordinary",
                "print('{\"type\":\"root_state\",\"status\":\"idle\"}',flush=True)",
            ),
        ] {
            let mut no_ack = spec(directory.path(), id);
            no_ack.command = "/usr/bin/python3".into();
            no_ack.args = vec!["-c".into(), output.into()];
            host.register(no_ack).await.unwrap();
            publish(
                &host.agent(id).unwrap(),
                json!({"type":"host_cancelled","cleanup_confirmed":true}),
            )
            .unwrap();
            assert!(matches!(
                host.restore_descendants(id).await,
                Err(HostError::Rejected(_))
            ));
            assert_eq!(
                host.status(id).await.unwrap()["runtime"]["status"],
                "cancelled"
            );
        }
        let mut expired = spec(directory.path(), "expired");
        expired.command = config.command.clone();
        expired.args = config.args.clone();
        std::fs::create_dir_all(&expired.state_dir).unwrap();
        std::fs::write(expired.state_dir.join("release"), "").unwrap();
        host.register(expired).await.unwrap();
        let timed = host.agent("expired").unwrap();
        publish(
            &timed,
            json!({"type":"accepted","id":"before-timeout","durable":true}),
        )
        .unwrap();
        publish(&timed, json!({"type":"host_deadline","deadline_at":1})).unwrap();
        resume_deadline(&host, &timed);
        assert_eq!(
            host.recorded_status("expired").unwrap().unwrap()["deadline_expired"],
            true
        );
        assert_eq!(
            host.restore_descendants("expired").await.unwrap()["type"],
            "host_restoration_complete"
        );
        assert_eq!(
            host.status("expired").await.unwrap()["runtime"]["status"],
            "unknown"
        );
        let timed_log = std::fs::read_to_string(&timed.log_path).unwrap();
        assert!(timed_log.contains("host_deadline_expired"));
        assert!(!timed_log.contains("host_resumed"));
        drop(timed);
        host.retire("creator").await.unwrap();
        host.shutdown().await;
        drop(agent);
        drop(host);
        let reopened = AgentHost::open(&path).unwrap();
        assert!(
            reopened.register(config).await.is_err(),
            "retirement survived host reopen"
        );
        reopened.shutdown().await;
    }

    #[tokio::test]
    async fn restoration_requires_matching_durable_admission_and_exclusive_journal() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let host = AgentHost::open(root.path().join("host")).unwrap();
        let parent = spec(root.path(), "parent");
        host.register(parent.clone()).await.unwrap();
        let caller = host.agent("parent").unwrap();
        let folder = parent.state_dir.join("children/child");
        for name in ["identity", "state", "workspace"] {
            std::fs::create_dir_all(folder.join(name)).unwrap();
        }
        std::fs::write(folder.join("state/fork.json"), "{}").unwrap();
        std::fs::write(folder.join("state/log.jsonl"), "").unwrap();
        let request = json!({"op":"restore","instance_id":"child",
            "identity":folder.join("identity"),"state":folder.join("state"),
            "workspace":folder.join("workspace"),"workspace_mode":"host",
            "seat":parent.seat_config,"initial_input":{"id":"first","type":"prompt","message":"original"}});
        assert!(handle(&host, &caller, 0, &request).await.is_err());
        assert_eq!(host.registered_agents(), vec!["parent"]);
        assert!(!host.root.join("child").exists());
        let child: Spawn = serde_json::from_value(request).unwrap();
        let directory = host.root.join("child");
        std::fs::create_dir(&directory).unwrap();
        let mut events = File::create(directory.join("events.jsonl")).unwrap();
        let record = |sequence, event| {
            serde_json::to_string(&HostEvent {
                sequence,
                agent_id: "child".into(),
                event,
            })
            .unwrap()
        };
        writeln!(
            events,
            "{}",
            record(
                1,
                json!({"type":"host_instance_registered","creator_id":"parent"})
            )
        )
        .unwrap();
        assert!(admitted_instance(&host, "parent", &child).is_err());
        writeln!(
            events,
            "{}",
            record(2, json!({"type":"accepted","id":"first","durable":true}))
        )
        .unwrap();
        events.sync_all().unwrap();
        assert!(admitted_instance(&host, "parent", &child).is_err());
        let mut inbox = File::create(child.state.join("inbox.jsonl")).unwrap();
        writeln!(
            inbox,
            "{}",
            json!({"kind":"input","input":child.initial_input})
        )
        .unwrap();
        inbox.sync_all().unwrap();
        assert!(admitted_instance(&host, "parent", &child).is_ok());
        assert!(matches!(
            admitted_instance(&host, "other", &child),
            Err(HostError::Forbidden)
        ));
        let mut altered = child;
        altered.initial_input.message = "different".into();
        assert!(matches!(
            admitted_instance(&host, "parent", &altered),
            Err(HostError::Forbidden)
        ));
        altered.initial_input.message = "original".into();
        let journal = File::open(altered.state.join("log.jsonl")).unwrap();
        fs2::FileExt::lock_exclusive(&journal).unwrap();
        assert!(matches!(
            admitted_instance(&host, "parent", &altered),
            Err(HostError::Busy)
        ));
        drop(journal);
        assert!(admitted_instance(&host, "parent", &altered).is_ok());
        host.shutdown().await;
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
        child.workspace = Some(root.path().into());
        assert!(matches!(
            child_spec(&parent, &child),
            Err(HostError::Forbidden)
        ));
        child.workspace = Some(folder.join("workspace"));
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
    async fn guest_workspace_stays_in_its_namespace_while_harness_starts_in_owned_state() {
        let root = tempfile::tempdir().unwrap();
        let mut parent = spec(root.path(), "parent");
        parent.workspace_mode = WorkspaceMode::Guest;
        parent.command = "/usr/bin/python3".into();
        parent.args = vec![
            "-c".into(),
            "import os,sys;print(os.getcwd());print(sys.argv[-1])".into(),
        ];
        let folder = parent.state_dir.join("children/child");
        for name in ["identity", "state"] {
            std::fs::create_dir_all(folder.join(name)).unwrap();
        }
        std::fs::write(folder.join("state/fork.json"), "{}").unwrap();
        let workspace = PathBuf::from("/guest-only-owned-workspace/child");
        assert!(!workspace.exists());
        let mut child: Spawn = serde_json::from_value(json!({
            "instance_id":"child","identity":folder.join("identity"),"state":folder.join("state"),
            "workspace":workspace,"workspace_mode":"guest","seat":parent.seat_config,
            "space":{"space_id":"new-child-space","isolation":"vm","workspace_root":workspace,"endpoint":"http://127.0.0.1:9/mcp"},
            "initial_input":{"id":"initial","message":"task"}
        })).unwrap();
        let registered = child_spec(&parent, &child).unwrap();
        let output = spawn(&registered)
            .unwrap()
            .wait_with_output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "{}\n{}\n",
                registered.state_dir.display(),
                workspace.display()
            )
        );
        child.workspace = Some("/guest-only-owned-workspace/../another-space".into());
        child.space.as_mut().unwrap().workspace_root = child.workspace.clone();
        assert!(matches!(
            child_spec(&parent, &child),
            Err(HostError::Forbidden)
        ));
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
            while !child.log.lock().unwrap().deadline_expired {
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
            "unknown"
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
        assert!(cancel(&host, "unbounded", false).await.is_err());
        assert_eq!(
            host.status("unbounded").await.unwrap()["runtime"]["status"],
            "unknown"
        );
        assert_eq!(
            host.status("unbounded").await.unwrap()["runtime"]["cleanup_confirmed"],
            false
        );
        assert!(deadline_at(Some(f64::NAN)).is_err());
        assert!(deadline_at(Some(-1.0)).is_err());
        assert!(deadline_at(Some(0.0)).is_err());
        host.shutdown().await;
    }
}
