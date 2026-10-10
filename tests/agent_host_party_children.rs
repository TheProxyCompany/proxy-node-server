#![cfg(feature = "agent-host")]
use proxy_node_server::agent_host::{
    AgentHost, AgentInput, AgentSpec, EventSubscription, WorkspaceMode,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

// This is a real process tree and real pipes. The fixture replaces inference,
// not Node's lifecycle, durable acknowledgement, or event demultiplexing.
const RUNTIME: &str = r#"#!/usr/bin/env python3
import os,sys,json,subprocess,threading,uuid
from pathlib import Path
state=Path(sys.argv[sys.argv.index('--state')+1]);state.mkdir(parents=True,exist_ok=True)
with (state/'starts').open('a') as f:f.write(str(os.getpid())+'\n')
(state/'ppid').write_text(str(os.getppid()))
output=threading.Lock()
def emit(v):
 with output: print(json.dumps(v),flush=True)
def ready():
 emit({'type':'root_readiness','ready':True,'agent_name':'fixture','checked_at':1,'components':{'model':{'ready':True,'status':'inference_verified'},'mcp':{'ready':True,'status':'tools_verified'},'memory':{'ready':True,'status':'journal_and_optchat_open'},'memory_adapters':{'ready':True},'life_map':{'ready':True}}})
 emit({'type':'root_state','status':'idle','fixture_pid':os.getpid(),'fixture_parent_pid':os.getppid()})
ready()
requests=[json.loads(x) for x in (state/'inputs').read_text().splitlines()] if (state/'inputs').exists() else []
pending=[]
def request(v):
 duplicate=any(x['id']==v['id'] for x in requests)
 if not duplicate:
  with (state/'inputs').open('a') as f:f.write(json.dumps(v)+'\n');f.flush();os.fsync(f.fileno())
  requests.append(v)
 emit({'type':'accepted','id':v['id'],'event_id':v['id'],'durable':True,'duplicate':duplicate})
 if v['message']=='hold': pending.append(v['id']);return
 emit({'type':'message_end','event_id':v['id'],'message':{'role':'assistant','content':[{'type':'text','text':v['message']}]}})
 emit({'type':'agent_settled','event_id':v['id'],'status':'done'})
def answer(v,data=None,error=None):
 emit({'type':'response','id':v['id'],'command':v['type'],'success':error is None,'data':data,'error':error})
for line in sys.stdin:
 v=json.loads(line);kind=v['type']
 if kind=='party_child_open':
  path=Path(v['spec']['state_dir']);path.mkdir(parents=True,exist_ok=True)
  (path/'fork.json').write_text(json.dumps({'creator':os.getpid(),'child_id':v['child_id']}))
  answer(v,{'child_id':v['child_id'],'fork_sha256':'a'*64})
 elif kind=='shutdown':
  emit({'type':'response','command':'shutdown','success':True});break
 elif kind=='abort':
  for ident in pending:emit({'type':'agent_settled','event_id':ident,'status':'aborted'})
  pending=[]
 else: request(v)
"#;

fn spec(root: &Path, id: &str) -> AgentSpec {
    use std::os::unix::fs::PermissionsExt;
    let binary = root.join("fixture-agent");
    std::fs::write(&binary, RUNTIME).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    AgentSpec {
        id: id.into(),
        display_name: None,
        command: binary,
        args: vec![],
        agent_dir: root.join("definition"),
        state_dir: root.join("state").join(id),
        workspace: root.into(),
        workspace_mode: WorkspaceMode::Host,
        seat_config: json!({"agent_id":"owner"}),
        env: BTreeMap::from([("SECRET".into(), "private-registration-token".into())]),
        space: None,
    }
}
fn input(id: &str, message: &str) -> AgentInput {
    AgentInput {
        id: id.into(),
        kind: "prompt".into(),
        message: message.into(),
        source: Some("party".into()),
        data: None,
        conversation_id: None,
        participant_id: None,
        task_id: Some("seat".into()),
    }
}
async fn event(sub: &mut EventSubscription, kind: &str, id: Option<&str>) -> Value {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let value = sub.recv().await.unwrap().event;
            if value["type"] == kind && id.is_none_or(|id| value["event_id"] == id) {
                return value;
            }
        }
    })
    .await
    .expect("expected fixture event")
}
async fn available(host: &AgentHost, id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let value = host.status(id).await.unwrap();
            if value["available"] == true {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected ready child")
}
fn log(root: &Path, id: &str) -> String {
    std::fs::read_to_string(root.join("host").join(id).join("events.jsonl")).unwrap()
}

#[tokio::test]
async fn party_instances_have_independent_processes_and_private_durable_streams() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "owner")).await.unwrap();
    host.register_party_child("owner", spec(temp.path(), "seat_a"))
        .await
        .unwrap();
    host.register_party_child("owner", spec(temp.path(), "seat_b"))
        .await
        .unwrap();
    let mut a = host.subscribe("seat_a", 0).unwrap();
    let mut b = host.subscribe("seat_b", 0).unwrap();
    let mut root = host.subscribe("owner", 0).unwrap();
    let (aa, bb, rr) = tokio::join!(
        host.submit("seat_a", input("same-id", "only-seat-a")),
        host.submit("seat_b", input("same-id", "only-seat-b")),
        host.submit("owner", input("same-id", "only-owner"))
    );
    assert_eq!(aa.unwrap()["durable"], true);
    assert_eq!(bb.unwrap()["durable"], true);
    assert_eq!(rr.unwrap()["durable"], true);
    event(&mut a, "agent_settled", Some("same-id")).await;
    event(&mut b, "agent_settled", Some("same-id")).await;
    event(&mut root, "agent_settled", Some("same-id")).await;
    let first = available(&host, "seat_a").await;
    let other = available(&host, "seat_b").await;
    let owner = available(&host, "owner").await;
    assert_eq!(first["creator_id"], "owner");
    assert_eq!(other["creator_id"], "owner");
    assert_eq!(first["address"], "/client/agents/seat_a");
    assert_ne!(first["pid"], other["pid"]);
    assert_ne!(first["pid"], owner["pid"]);
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/seat_a/ppid")).unwrap(),
        std::process::id().to_string()
    );
    host.ensure_started("seat_a").await.unwrap();
    assert_eq!(host.status("seat_a").await.unwrap()["pid"], first["pid"]);
    assert_eq!(
        host.submit("seat_a", input("same-id", "only-seat-a"))
            .await
            .unwrap()["duplicate"],
        true
    );
    event(&mut a, "agent_settled", Some("same-id")).await;
    let la = log(temp.path(), "seat_a");
    let lb = log(temp.path(), "seat_b");
    let lr = log(temp.path(), "owner");
    assert!(
        la.contains("only-seat-a")
            && !la.contains("only-seat-b")
            && !la.contains("stale private content")
    );
    assert!(lb.contains("only-seat-b") && !lb.contains("only-seat-a"));
    assert!(
        lr.contains("only-owner")
            && !lr.contains("only-seat-a")
            && !lr.contains("only-seat-b")
            && !lr.contains("party_child_event")
            && !lr.contains("child refused by parent")
    );
    for bytes in [la, lb, lr] {
        assert!(!bytes.contains("private-registration-token"));
    }
    host.shutdown().await;
    assert_eq!(host.status("seat_a").await.unwrap()["hosted"], false);
}

#[tokio::test]
async fn party_instance_survives_creator_sigkill_with_the_same_pid_and_address() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "owner")).await.unwrap();
    for id in ["seat_a", "seat_b"] {
        host.register_party_child("owner", spec(temp.path(), id))
            .await
            .unwrap();
    }
    let mut a = host.subscribe("seat_a", 0).unwrap();
    let mut b = host.subscribe("seat_b", 0).unwrap();
    host.submit("seat_a", input("hold-a", "hold"))
        .await
        .unwrap();
    host.submit("seat_b", input("hold-b", "hold"))
        .await
        .unwrap();
    let old_a = available(&host, "seat_a").await;
    let old_b = available(&host, "seat_b").await;
    host.abort("seat_a").await.unwrap();
    assert_eq!(
        event(&mut a, "agent_settled", Some("hold-a")).await["status"],
        "aborted"
    );
    assert!(!log(temp.path(), "seat_b").contains("aborted"));
    host.stop("seat_a").await.unwrap();
    assert_eq!(host.status("seat_a").await.unwrap()["hosted"], false);
    assert_eq!(host.status("seat_b").await.unwrap()["pid"], old_b["pid"]);
    host.submit("seat_a", input("reopened", "new-child"))
        .await
        .unwrap();
    event(&mut a, "agent_settled", Some("reopened")).await;
    let reopened = available(&host, "seat_a").await;
    assert_ne!(reopened["pid"], old_a["pid"]);
    let old_owner = host.status("owner").await.unwrap()["pid"].clone();
    let mut owner_events = host.subscribe("owner", 0).unwrap();
    assert!(
        std::process::Command::new("/bin/kill")
            .args(["-KILL", &old_owner.to_string()])
            .status()
            .unwrap()
            .success()
    );
    event(&mut owner_events, "host_process_exit", None).await;
    assert_eq!(host.status("seat_b").await.unwrap()["pid"], old_b["pid"]);
    assert_eq!(
        host.status("seat_b").await.unwrap()["address"],
        old_b["address"]
    );
    host.submit("seat_b", input("after-restart", "continued-child"))
        .await
        .unwrap();
    event(&mut b, "agent_settled", Some("after-restart")).await;
    let final_owner = available(&host, "owner").await;
    assert_ne!(final_owner["pid"], old_owner);
    assert_eq!(host.status("seat_b").await.unwrap()["pid"], old_b["pid"]);
    host.stop("owner").await.unwrap();
    assert_eq!(host.status("seat_b").await.unwrap()["hosted"], true);
    host.submit("seat_b", input("creator-stopped", "still-reachable"))
        .await
        .unwrap();
    event(&mut b, "agent_settled", Some("creator-stopped")).await;
    assert_eq!(host.status("seat_b").await.unwrap()["pid"], old_b["pid"]);
    host.shutdown().await;
}

#[tokio::test]
async fn party_registration_preserves_creator_without_coupling_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "owner")).await.unwrap();
    host.register(spec(temp.path(), "other")).await.unwrap();
    let seat = spec(temp.path(), "seat");
    host.register_party_child("owner", seat.clone())
        .await
        .unwrap();
    assert!(host.register(seat.clone()).await.is_err());
    assert!(
        host.register_party_child("other", seat.clone())
            .await
            .is_err()
    );
    assert!(
        host.register_party_child("seat", spec(temp.path(), "nested"))
            .await
            .is_err()
    );
    let mut wrong = spec(temp.path(), "wrong");
    wrong.command = temp.path().join("another-command");
    assert!(host.register_party_child("owner", wrong).await.is_err());
    let mut wrong = spec(temp.path(), "wrong");
    wrong.state_dir = spec(temp.path(), "owner").state_dir;
    assert!(host.register_party_child("owner", wrong).await.is_err());
    host.submit("seat", input("busy", "hold")).await.unwrap();
    let mut changed = spec(temp.path(), "owner");
    changed.seat_config["model"] = "new".into();
    host.register(changed).await.unwrap();
    assert!(!temp.path().join("state/other").exists());
    host.shutdown().await;
}

#[tokio::test]
async fn retired_handles_cannot_restart_and_keep_their_read_only_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let stale = host.clone();
    host.register(spec(temp.path(), "legacy")).await.unwrap();
    let mut history = stale.subscribe("legacy", 0).unwrap();
    host.submit("legacy", input("before-cutover", "durable-old-receipt"))
        .await
        .unwrap();
    event(&mut history, "agent_settled", Some("before-cutover")).await;
    host.retire("legacy").await.unwrap();
    event(&mut history, "host_retired", None).await;
    let status = stale.status("legacy").await.unwrap();
    assert_eq!(status["retired"], true);
    assert_eq!(status["hosted"], false);
    assert_eq!(status["pid"], Value::Null);
    assert!(stale.ensure_started("legacy").await.is_err());
    assert!(
        stale
            .submit("legacy", input("after-cutover", "must-not-run"))
            .await
            .is_err()
    );
    assert!(stale.register(spec(temp.path(), "legacy")).await.is_err());
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/legacy/starts"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(log(temp.path(), "legacy").contains("durable-old-receipt"));
    assert!(!log(temp.path(), "legacy").contains("must-not-run"));
    let mut reopened = stale.subscribe("legacy", 0).unwrap();
    event(&mut reopened, "agent_settled", Some("before-cutover")).await;
    // Offline migration can tombstone an id without creating old runtime state.
    host.retire("never-registered").await.unwrap();
    host.retire("never-registered").await.unwrap();
    assert!(
        stale
            .register(spec(temp.path(), "never-registered"))
            .await
            .is_err()
    );
    assert!(stale.ensure_started("never-registered").await.is_err());
    assert!(!temp.path().join("host/never-registered").exists());
    assert!(!temp.path().join("state/never-registered").exists());
    assert!(host.retire("../invalid").await.is_err());
    // Child retirement drains and stops the actual owned process too.
    host.register(spec(temp.path(), "owner")).await.unwrap();
    host.register_party_child("owner", spec(temp.path(), "seat"))
        .await
        .unwrap();
    host.submit("seat", input("seat-before", "child-receipt"))
        .await
        .unwrap();
    host.retire("seat").await.unwrap();
    assert_eq!(host.status("seat").await.unwrap()["pid"], Value::Null);
    assert!(
        stale
            .submit("seat", input("seat-after", "must-not-run"))
            .await
            .is_err()
    );
    assert!(
        stale
            .register_party_child("owner", spec(temp.path(), "seat"))
            .await
            .is_err()
    );
    host.retire("owner").await.unwrap();
    assert!(
        stale
            .register_party_child("owner", spec(temp.path(), "another-seat"))
            .await
            .is_err()
    );
    host.shutdown().await;
}

#[tokio::test]
async fn a_logical_creator_needs_no_native_process_and_cannot_replace_existing_context() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let instance = spec(temp.path(), "standalone");
    host.register_spawned("external-creator", instance.clone())
        .await
        .unwrap();
    let mut events = host.subscribe("standalone", 0).unwrap();
    host.submit("standalone", input("first", "standalone-context"))
        .await
        .unwrap();
    event(&mut events, "agent_settled", Some("first")).await;
    let original = host.status("standalone").await.unwrap();
    assert_eq!(original["creator_id"], "external-creator");
    assert!(host.status("external-creator").await.is_err());
    assert!(!instance.state_dir.join("fork.json").exists());
    // PH creates this journal when opening its own context, before publishing readiness.
    std::fs::write(instance.state_dir.join("log.jsonl"), "").unwrap();
    host.register(spec(temp.path(), "external-creator"))
        .await
        .unwrap();
    host.ensure_started("standalone").await.unwrap();
    assert_eq!(
        host.status("standalone").await.unwrap()["pid"],
        original["pid"]
    );
    host.stop("standalone").await.unwrap();
    host.submit("standalone", input("reattached", "same-context"))
        .await
        .unwrap();
    event(&mut events, "agent_settled", Some("reattached")).await;
    assert!(!instance.state_dir.join("fork.json").exists());
    assert_eq!(
        host.status("external-creator").await.unwrap()["pid"],
        Value::Null
    );
    host.retire("external-creator").await.unwrap();
    host.register_spawned("external-creator", instance.clone())
        .await
        .unwrap();
    host.submit("standalone", input("creator-retired", "still-independent"))
        .await
        .unwrap();
    event(&mut events, "agent_settled", Some("creator-retired")).await;
    host.shutdown().await;
}
