#![cfg(feature = "agent-host")]
use proxy_node_server::agent_host::{
    AgentHost, AgentInput, AgentSpec, EventSubscription, HostError, WorkspaceMode,
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
children={}
def envelope(c,event):
 return {'type':'party_child_event','child_id':c['id'],'instance_id':c['instance'],'pid':c['p'].pid,'parent_pid':os.getpid(),'event':event}
def relay(c):
 for line in c['p'].stdout: emit(envelope(c,json.loads(line)))
def stop(c):
 c['p'].terminate();c['p'].wait();c['thread'].join()
 emit(envelope(c,{'type':'host_process_exit','code':0}))
def answer(v,data=None,error=None):
 emit({'type':'response','id':v['id'],'command':v['type'],'success':error is None,'data':data,'error':error})
for line in sys.stdin:
 v=json.loads(line);kind=v['type']
 if kind=='party_child_open':
  ident=v['child_id']
  if ident not in children:
   s=v['spec'];env=os.environ.copy();env.update(s['env'])
   p=subprocess.Popen([sys.executable,sys.argv[0],'--child','--state',s['state_dir']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env=env)
   c={'id':ident,'instance':uuid.uuid4().hex,'p':p};children[ident]=c
   c['thread']=threading.Thread(target=relay,args=(c,),daemon=True)
   answer(v,{'child_id':ident,'instance_id':c['instance'],'pid':p.pid,'parent_pid':os.getpid(),'fork_sha256':'a'*64})
   c['thread'].start()
  else:
   c=children[ident];answer(v,{'child_id':ident,'instance_id':c['instance'],'pid':c['p'].pid,'parent_pid':os.getpid(),'fork_sha256':'a'*64})
 elif kind=='party_child_send':
  ident=v['child_id'];inp=v['input'];c=children.get(ident)
  if inp['message']=='exit-before-accept':
   for item in children.values():stop(item)
   os._exit(17)
  if not c or inp['message']=='reject-parent':
   emit({'type':'response','command':'party_child_send','child_id':ident,'id':inp['id'],'success':False,'error':'child refused by parent'});continue
  if inp['message']=='stale':
   stale=envelope(c,{'type':'accepted','event_id':inp['id'],'durable':True,'forged':True});stale['instance_id']='old-instance';emit(stale)
   stale=envelope(c,{'type':'message_end','event_id':inp['id'],'text':'stale private content'});stale['pid']+=1;emit(stale)
  c['p'].stdin.write(json.dumps(inp)+'\n');c['p'].stdin.flush()
 elif kind=='party_child_abort':
  c=children[v['child_id']];c['p'].stdin.write(json.dumps({'type':'abort'})+'\n');c['p'].stdin.flush();answer(v,{})
 elif kind=='party_child_stop':
  c=children.pop(v['child_id'],None)
  if c:stop(c)
  answer(v,{})
 elif kind=='abort':
  for ident in pending:emit({'type':'agent_settled','event_id':ident,'status':'aborted'})
  pending=[]
 else: request(v)
for c in children.values():stop(c)
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
async fn party_children_have_real_parent_pids_and_private_durable_streams() {
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
    assert_eq!(first["party_child"]["launch"]["parent_pid"], owner["pid"]);
    assert_eq!(other["party_child"]["launch"]["parent_pid"], owner["pid"]);
    assert_ne!(first["pid"], other["pid"]);
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/seat_a/ppid")).unwrap(),
        owner["pid"].to_string()
    );
    host.ensure_started("seat_a").await.unwrap();
    assert_eq!(
        host.status("seat_a").await.unwrap()["party_child"],
        first["party_child"]
    );
    assert_eq!(
        host.submit("seat_a", input("same-id", "only-seat-a"))
            .await
            .unwrap()["duplicate"],
        true
    );
    event(&mut a, "agent_settled", Some("same-id")).await;
    let ack = host
        .submit("seat_a", input("stale-check", "stale"))
        .await
        .unwrap();
    assert!(ack.get("forged").is_none());
    event(&mut a, "agent_settled", Some("stale-check")).await;
    assert!(matches!(
        host.submit("seat_a", input("refused", "reject-parent"))
            .await,
        Err(HostError::Rejected(_))
    ));
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
async fn party_child_abort_stop_and_parent_restart_preserve_ownership() {
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
    assert_ne!(
        reopened["party_child"]["launch"]["instance_id"],
        old_a["party_child"]["launch"]["instance_id"]
    );
    let old_owner = host.status("owner").await.unwrap()["pid"].clone();
    assert!(matches!(
        host.submit("seat_a", input("unknown", "exit-before-accept"))
            .await,
        Err(HostError::AcceptanceUnknown)
    ));
    assert_eq!(host.status("seat_b").await.unwrap()["available"], false);
    host.submit("seat_b", input("after-restart", "resumed-child"))
        .await
        .unwrap();
    event(&mut b, "agent_settled", Some("after-restart")).await;
    let final_b = available(&host, "seat_b").await;
    let final_owner = available(&host, "owner").await;
    assert_ne!(final_owner["pid"], old_owner);
    assert_ne!(
        final_b["party_child"]["launch"]["instance_id"],
        old_b["party_child"]["launch"]["instance_id"]
    );
    assert_eq!(
        final_b["party_child"]["launch"]["parent_pid"],
        final_owner["pid"]
    );
    host.stop("owner").await.unwrap();
    assert_eq!(host.status("seat_b").await.unwrap()["hosted"], false);
    assert_eq!(host.status("seat_b").await.unwrap()["pid"], Value::Null);
    host.shutdown().await;
}

#[tokio::test]
async fn party_registration_rejects_reparenting_and_standalone_fallback() {
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
    assert!(matches!(host.register(changed).await, Err(HostError::Busy)));
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
