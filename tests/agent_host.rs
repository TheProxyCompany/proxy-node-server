#![cfg(feature = "agent-host")]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use proxy_node_server::agent_host::http::{HostOperation, router};
use proxy_node_server::agent_host::{
    AgentHost, AgentInput, AgentSpec, EventSubscription, HostError, WorkspaceMode,
};
use serde_json::{Value, json};

const RUNTIME: &str = r#"#!/usr/bin/env python3
import sys,os,json,time
from pathlib import Path
state=Path(sys.argv[sys.argv.index('--state')+1]); state.mkdir(parents=True,exist_ok=True)
with (state/'starts').open('a') as f: f.write(str(os.getpid())+'\n')
def emit(v): print(json.dumps(v),flush=True)
# Match the real runtime: initial state precedes readiness.
emit({'type':'root_state','status':'idle','input_id':None,'queue_depth':0})
ready=json.loads(os.environ.get('PROXY_HARNESS_SEAT','{}')).get('readiness')
if ready:
 emit({'type':'root_readiness','ready':True,'agent_name':'fixture','checked_at':1,'components':{'model':{'ready':True,'status':'inference_verified'},'mcp':{'ready':True,'status':'tools_verified'},'memory':{'ready':ready!='memory_missing','status':'journal_and_optchat_open'},'memory_adapters':{'ready':True},'life_map':{'ready':True,'required':True,'status':'read'}},'work_ahead':['fixture-goal']})
def save(name,v):
 with (state/name).open('a') as f: f.write(json.dumps(v)+'\n'); f.flush(); os.fsync(f.fileno())
requests=[json.loads(x) for x in (state/'inputs').read_text().splitlines()] if (state/'inputs').exists() else []
done=set((state/'done').read_text().splitlines()) if (state/'done').exists() else set()
def finish(v):
 emit({'type':'root_state','status':'running','input_id':v['id'],'queue_depth':0})
 if v['message']=='slow': time.sleep(.3)
 model=json.loads(os.environ.get('PROXY_HARNESS_SEAT','{}')).get('model','fixture')
 emit({'type':'message_end','event_id':v['id'],'message':{'role':'assistant','content':[{'type':'text','text':v['message']+':'+model}]}})
 with (state/'done').open('a') as f: f.write(v['id']+'\n'); f.flush(); os.fsync(f.fileno())
 done.add(v['id'])
 emit({'type':'agent_settled','event_id':v['id'],'status':'done'})
 emit({'type':'root_state','status':'idle','input_id':None,'queue_depth':0})
for v in requests:
 if v['id'] not in done: finish(v)
for line in sys.stdin:
 v=json.loads(line)
 if v['type']=='shutdown': emit({'type':'response','command':'shutdown','success':'REJECT_SHUTDOWN' not in os.environ}); break
 if v['type']=='abort': emit({'type':'root_state','status':'idle'}); continue
 if v['message']=='reject': emit({'type':'response','success':False,'event_id':v['id'],'error':'refused'}); continue
 duplicate=any(x['id']==v['id'] for x in requests)
 if not duplicate: save('inputs',v); requests.append(v)
 emit({'type':'accepted','id':v['id'],'event_id':v['id'],'durable':True,'duplicate':duplicate})
 if v['id'] in done:
  emit({'type':'agent_settled','event_id':v['id'],'status':'done','duplicate':True}); continue
 if v['message']=='crash' and not (state/'crashed').exists():
  (state/'crashed').touch(); os._exit(17)
 finish(v)
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
        agent_dir: root.join("identity"),
        state_dir: root.join("state").join(id),
        workspace: root.into(),
        workspace_mode: WorkspaceMode::Host,
        seat_config: json!({"model":"original"}),
        space: None,
        env: BTreeMap::from([(
            "FAKE_API_KEY".into(),
            "never-persist-this-credential".into(),
        )]),
    }
}

fn input(id: &str, message: &str) -> AgentInput {
    AgentInput {
        id: id.into(),
        kind: "prompt".into(),
        message: message.into(),
        source: Some("test".into()),
        data: None,
        conversation_id: Some("conversation".into()),
        participant_id: None,
        task_id: None,
    }
}

async fn settled(sub: &mut EventSubscription, id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let event = sub.recv().await.unwrap();
            if event.event["type"] == "agent_settled" && event.event["event_id"] == id {
                return event.event;
            }
        }
    })
    .await
    .expect("runtime did not settle")
}

#[tokio::test]
async fn disconnected_reader_does_not_kill_root_and_ids_deduplicate() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "dot")).await.unwrap();
    let mut first = host.subscribe("dot", 0).unwrap();
    let ack = host.submit("dot", input("one", "slow")).await.unwrap();
    assert_eq!(ack["durable"], true);
    let pid = host.status("dot").await.unwrap()["pid"].clone();
    drop(first);
    first = host.subscribe("dot", 0).unwrap();
    settled(&mut first, "one").await;
    let ack = host.submit("dot", input("one", "slow")).await.unwrap();
    assert_eq!(ack["duplicate"], true);
    settled(&mut first, "one").await;
    assert_eq!(host.status("dot").await.unwrap()["pid"], pid);
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/dot/inputs"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(
        !std::fs::read_to_string(temp.path().join("host/dot/events.jsonl"))
            .unwrap()
            .contains("never-persist-this-credential")
    );
    host.shutdown().await;
}

#[tokio::test]
async fn accepted_work_resumes_after_process_crash() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "dot")).await.unwrap();
    let mut sub = host.subscribe("dot", 0).unwrap();
    host.submit("dot", input("recover", "crash")).await.unwrap();
    settled(&mut sub, "recover").await;
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/dot/starts"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/dot/inputs"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    host.shutdown().await;
}

#[tokio::test]
async fn configuration_changes_refuse_busy_and_restart_idle_without_losing_history() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let original = spec(temp.path(), "dot");
    host.register(original.clone()).await.unwrap();
    let mut sub = host.subscribe("dot", 0).unwrap();
    host.submit("dot", input("one", "slow")).await.unwrap();
    let mut changed = original;
    changed.seat_config = json!({"model":"updated"});
    assert!(matches!(
        host.register(changed.clone()).await,
        Err(HostError::Busy)
    ));
    settled(&mut sub, "one").await;
    host.register(changed).await.unwrap();
    host.submit("dot", input("two", "next")).await.unwrap();
    let mut updated = false;
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap();
        if event.event["type"] == "message_end" {
            updated |= event.event.to_string().contains("next:updated");
        }
        if event.event["type"] == "agent_settled" && event.event["event_id"] == "two" {
            break;
        }
    }
    assert!(updated);
    host.shutdown().await;
}

#[tokio::test]
async fn event_history_reopens_after_host_restart_and_host_lease_is_exclusive() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("host");
    let host = AgentHost::open(&directory).unwrap();
    assert!(matches!(AgentHost::open(&directory), Err(HostError::Busy)));
    let configured = spec(temp.path(), "dot");
    host.register(configured.clone()).await.unwrap();
    let mut sub = host.subscribe("dot", 0).unwrap();
    host.submit("dot", input("one", "kept")).await.unwrap();
    settled(&mut sub, "one").await;
    host.shutdown().await;
    drop(sub);
    drop(host);
    tokio::task::yield_now().await;
    let host = AgentHost::open(&directory).unwrap();
    host.register(configured).await.unwrap();
    let mut replay = host.subscribe("dot", 0).unwrap();
    settled(&mut replay, "one").await;
    assert_eq!(host.status("dot").await.unwrap()["pid"], Value::Null);
    host.shutdown().await;
}

#[tokio::test]
async fn canonical_host_restart_recovers_admitted_work_after_a_failed_start_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("host");
    let configured = spec(temp.path(), "dot");
    let host = AgentHost::open(&directory).unwrap();
    host.register(configured.clone()).await.unwrap();
    assert_eq!(
        host.submit("dot", input("retained", "slow")).await.unwrap()["durable"],
        true
    );
    // A crash leaves admission unresolved. An explicit shutdown now asks the
    // runtime to cancel active work before the host closes its process.
    let pid = host.status("dot").await.unwrap()["pid"].as_u64().unwrap();
    assert!(
        std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    host.shutdown().await;
    drop(host);
    tokio::task::yield_now().await;

    // A previous host's invalid launch configuration is never persisted as
    // the authority of a later host. It must not erase the runtime's inbox.
    let failed = AgentHost::open(&directory).unwrap();
    let mut poisoned = configured.clone();
    poisoned.command = "/usr/bin/false".into();
    failed.register(poisoned).await.unwrap();
    let cursor = failed.status("dot").await.unwrap()["sequence"]
        .as_u64()
        .unwrap();
    let mut exits = failed.subscribe("dot", cursor).unwrap();
    failed.ensure_started("dot").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if exits.recv().await.unwrap().event["type"] == "host_process_exit" {
                break;
            }
        }
    })
    .await
    .unwrap();
    failed.shutdown().await;
    drop(exits);
    drop(failed);
    tokio::task::yield_now().await;

    let restored = AgentHost::open(&directory).unwrap();
    restored.register(configured.clone()).await.unwrap();
    let cursor = restored.status("dot").await.unwrap()["sequence"]
        .as_u64()
        .unwrap();
    let mut recovered = restored.subscribe("dot", cursor).unwrap();
    restored.ensure_started("dot").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let event = recovered.recv().await.unwrap().event;
            if event["type"] == "root_state" && event["status"] == "running" {
                break;
            }
        }
    })
    .await
    .unwrap();
    let mut changed = configured;
    changed.seat_config = json!({"model":"different"});
    assert!(matches!(
        restored.register(changed).await,
        Err(HostError::Busy)
    ));
    settled(&mut recovered, "retained").await;
    assert_eq!(
        restored
            .submit("dot", input("retained", "slow"))
            .await
            .unwrap()["duplicate"],
        true
    );
    settled(&mut recovered, "retained").await;
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/dot/inputs"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/dot/done"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    restored.shutdown().await;
}

#[tokio::test]
async fn http_requires_the_exact_agent_grant_and_durable_ack() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "dot")).await.unwrap();
    let authority = Arc::new(
        |headers: &axum::http::HeaderMap, id: &str, _operation: HostOperation| {
            if id == "dot"
                && headers.get("authorization").and_then(|x| x.to_str().ok())
                    == Some("Bearer dot-only")
            {
                Ok(())
            } else {
                Err(HostError::Forbidden)
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, router(host.clone(), authority)).into_future());
    let client = reqwest::Client::new();
    let base = format!("http://{address}");
    assert_eq!(
        client
            .get(format!("{base}/client/agents/dot/status"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{base}/muse"))
            .bearer_auth("dot-only")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = client
        .post(format!("{base}/client/agents/dot/input"))
        .bearer_auth("dot-only")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&input("one", "hello")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["durable"], true);
    let requests = std::fs::read_to_string(temp.path().join("state/dot/inputs")).unwrap();
    assert!(requests.contains("address-client"));
    let response = host.submit("dot", input("bad", "reject")).await;
    assert!(matches!(response, Err(HostError::Rejected(_))));
    host.shutdown().await;
    server.abort();
}

#[test]
fn pact_identity_enforces_signature_audience_and_time_and_checks_receipts() {
    use proxy_node_server::DeviceIdentity;
    use proxy_node_server::agent_host::pact::{PactIdentity, verify_identity, verify_receipt};
    let identity = PactIdentity::new(
        "https://pa.example".into(),
        Arc::new(DeviceIdentity::generate()),
    )
    .unwrap();
    let key = identity.jwks();
    let token = identity
        .token("opaque-user", "assigned-audience", 1000)
        .unwrap();
    assert_eq!(
        verify_identity(
            &token,
            &key,
            "https://pa.example",
            "assigned-audience",
            1020
        )
        .unwrap()["sub"],
        "opaque-user"
    );
    for (issuer, audience, time) in [
        ("https://other.example", "assigned-audience", 1020),
        ("https://pa.example", "wrong", 1020),
        ("https://pa.example", "assigned-audience", 900),
        ("https://pa.example", "assigned-audience", 1200),
    ] {
        assert!(verify_identity(&token, &key, issuer, audience, time).is_err());
    }
    let bad=identity.sign_claims(&json!({"iss":"https://pa.example","sub":"opaque-user","aud":"assigned-audience","iat":1000,"exp":1400})).unwrap();
    assert!(verify_identity(&bad, &key, "https://pa.example", "assigned-audience", 1020).is_err());
    let other = PactIdentity::new(
        "https://pa.example".into(),
        Arc::new(DeviceIdentity::generate()),
    )
    .unwrap();
    assert!(
        verify_identity(
            &token,
            &other.jwks(),
            "https://pa.example",
            "assigned-audience",
            1020
        )
        .is_err()
    );
    let claims = json!({"grantId":"grant","user":"brand-user","pa":"https://pa.example","brand":"https://brand.example/a2a/shop","scopesUsed":["orders:read"],"actions":[{"tool":"lookup_orders"}],"ts":"2026-10-07T00:00:00Z"});
    let mut reply = json!({"message":{"metadata":{"pact.receipt":{"jws":identity.sign_claims(&claims).unwrap(),"claims":claims}}}});
    assert!(
        verify_receipt(
            &reply,
            &key,
            "grant",
            "brand-user",
            "https://pa.example",
            "https://brand.example/a2a/shop",
            &["orders:read".into()]
        )
        .is_ok()
    );
    reply["message"]["metadata"]["pact.receipt"]["claims"]["actions"] = json!([]);
    assert!(
        verify_receipt(
            &reply,
            &key,
            "grant",
            "brand-user",
            "https://pa.example",
            "https://brand.example/a2a/shop",
            &["orders:read".into()]
        )
        .is_err()
    );
}

#[test]
fn pact_verifies_rs256_provider_keys() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use proxy_node_server::agent_host::pact::verify_identity;
    use rsa::{
        RsaPrivateKey,
        signature::{SignatureEncoding, Signer},
        traits::PublicKeyParts,
    };
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let public = private.to_public_key();
    let jwks = json!({"keys":[{"kty":"RSA","kid":"rsa-test","alg":"RS256","n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]});
    let head = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({"alg":"RS256","kid":"rsa-test"})).unwrap());
    let body=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://pa.example","sub":"opaque","aud":"assigned","iat":1000,"exp":1120})).unwrap());
    let input = format!("{head}.{body}");
    let signature =
        rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private).sign(input.as_bytes());
    let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    assert!(verify_identity(&token, &jwks, "https://pa.example", "assigned", 1000).is_ok());
}

#[tokio::test]
async fn pact_http_binds_context_to_identity_and_replays_without_rerunning() {
    use proxy_node_server::DeviceIdentity;
    use proxy_node_server::agent_host::pact::{PactClient, PactIdentity, verify_identity};
    use proxy_node_server::agent_host::pact_server::{self, PactPrincipal, PublishedAgent};
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    host.register(spec(temp.path(), "dot")).await.unwrap();
    let caller = Arc::new(
        PactIdentity::new(
            "https://pa.example".into(),
            Arc::new(DeviceIdentity::generate()),
        )
        .unwrap(),
    );
    let provider = Arc::new(
        PactIdentity::new(
            "https://proxy.example".into(),
            Arc::new(DeviceIdentity::generate()),
        )
        .unwrap(),
    );
    let keys = caller.jwks();
    let authority = Arc::new(move |headers: &axum::http::HeaderMap, agent: &str| {
        if agent != "dot" {
            return Err(HostError::Forbidden);
        }
        let token = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or(HostError::Forbidden)?;
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = verify_identity(
            token,
            &keys,
            "https://pa.example",
            "provider-assigned",
            time,
        )?;
        Ok(PactPrincipal {
            issuer: claims["iss"].as_str().unwrap().into(),
            subject: claims["sub"].as_str().unwrap().into(),
        })
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let make_router = || {
        pact_server::router(
            host.clone(),
            provider.clone(),
            authority.clone(),
            temp.path().join("pact"),
            &base,
            vec![PublishedAgent {
                id: "dot".into(),
                name: "Dot".into(),
                description: "Fixture".into(),
            }],
        )
        .unwrap()
        .route(
            "/public-card",
            axum::routing::get(|| async {
                axum::response::Redirect::temporary("/a2a/dot/.well-known/agent-card.json")
            }),
        )
    };
    let server = tokio::spawn(axum::serve(listener, make_router()).into_future());
    let raw = reqwest::Client::new();
    let unauthorized = raw
        .post(format!("{base}/a2a/dot/message:send"))
        .body("bad json")
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);
    assert_eq!(
        unauthorized.headers()["www-authenticate"],
        "Bearer realm=\"a2a\""
    );
    assert!(unauthorized.bytes().await.unwrap().is_empty());
    assert_eq!(
        raw.post(format!("{base}/a2a/unknown/message:send"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let client = Arc::new(
        PactClient::new(
            caller.clone(),
            "person-a".into(),
            "provider-assigned".into(),
        )
        .unwrap(),
    );
    let peer = Arc::new(
        client
            .discover(&format!("{base}/public-card"))
            .await
            .unwrap(),
    );
    let first = client
        .send(&peer, "one", "hello", None, None)
        .await
        .unwrap();
    assert_eq!(first["message"]["role"], "ROLE_AGENT");
    assert_eq!(first["message"]["parts"][0]["text"], "hello:original");
    let context = first["message"]["contextId"].as_str().unwrap();
    assert_eq!(
        client
            .send(&peer, "one", "changed duplicate", Some(context), None)
            .await
            .unwrap(),
        first
    );
    let stranger = PactClient::new(
        caller.clone(),
        "person-b".into(),
        "provider-assigned".into(),
    )
    .unwrap();
    assert!(
        matches!(stranger.send(&peer,"two","foreign",Some(context),None).await,Err(HostError::Rejected(ref reason)) if reason=="INVALID_PARAMS")
    );
    let second = client
        .send(&peer, "two", "continued", Some(context), None)
        .await
        .unwrap();
    assert_eq!(second["message"]["contextId"], context);
    let ongoing = {
        let client = client.clone();
        let peer = peer.clone();
        let context = context.to_string();
        tokio::spawn(async move {
            client
                .send(&peer, "three", "slow", Some(&context), None)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        matches!(client.send(&peer,"three","slow",Some(context),None).await,Err(HostError::Rejected(ref reason)) if reason=="INVALID_PARAMS")
    );
    ongoing.await.unwrap().unwrap();
    server.abort();
    let _ = server.await;
    let client = PactClient::new(
        caller.clone(),
        "person-a".into(),
        "provider-assigned".into(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind(base.trim_start_matches("http://"))
        .await
        .unwrap();
    let server = tokio::spawn(axum::serve(listener, make_router()).into_future());
    assert_eq!(
        client
            .send(&peer, "one", "again", Some(context), None)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/dot/inputs"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    host.shutdown().await;
    server.abort();
}

#[tokio::test]
#[ignore = "requires an explicitly created isolated Herdr session and pane"]
async fn herdr_live_reports_and_releases_only_the_supplied_test_pane() {
    use proxy_node_server::agent_host::herdr::HerdrBridge;
    let binary = std::env::var("PROXY_TEST_HERDR_BIN").expect("isolated Herdr binary");
    let socket = std::env::var("PROXY_TEST_HERDR_SOCKET").expect("isolated Herdr socket");
    let pane = std::env::var("PROXY_TEST_HERDR_PANE").expect("isolated Herdr pane");
    let bridge = HerdrBridge::new(
        binary.clone().into(),
        socket.clone(),
        pane.clone(),
        "proxy-harness-proof".into(),
        vec![],
    )
    .unwrap();
    for status in ["working", "blocked", "idle"] {
        bridge.report(status).await.unwrap();
        let output = tokio::process::Command::new(&binary)
            .args(["pane", "get", &pane])
            .env("HERDR_SOCKET_PATH", &socket)
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let state: Value = serde_json::from_slice(&output.stdout).unwrap();
        let actual = &state["result"]["pane"]["agent_status"];
        assert!(
            actual == status || (status == "idle" && actual == "done"),
            "{state}"
        );
        println!("Herdr observed {status}: {state}");
    }
    bridge.release().await.unwrap();
    let output = tokio::process::Command::new(&binary)
        .args(["pane", "get", &pane])
        .env("HERDR_SOCKET_PATH", &socket)
        .output()
        .await
        .unwrap();
    let state: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(state["result"]["pane"].get("agent").is_none());
    println!("Herdr released: {state}");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn native_process_uses_agent_name_in_ps() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let mut definition = spec(temp.path(), "dot");
    definition.command = "/bin/sh".into();
    definition.args = vec!["-c".into(), "while IFS= read -r line; do :; done".into()];
    definition.display_name = Some("JarvisDot".into());
    host.register(definition).await.unwrap();
    host.ensure_started("dot").await.unwrap();
    let pid = host.status("dot").await.unwrap()["pid"].as_u64().unwrap();
    let output = tokio::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm=,args="])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let process = String::from_utf8(output.stdout).unwrap();
    assert!(process.trim_start().starts_with("JarvisDot"), "{process}");
    println!("Observed native process name: {process}");
    host.shutdown().await;
}

#[tokio::test]
async fn availability_requires_current_verified_components_and_clears_on_reconfigure() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let mut configured = spec(temp.path(), "ready");
    host.register(configured.clone()).await.unwrap();
    host.ensure_started("ready").await.unwrap();
    assert_eq!(host.status("ready").await.unwrap()["available"], false);
    // A spawned process is not yet known to be idle: wait for its initial state.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if host.status("ready").await.unwrap()["runtime"]["status"] == "idle" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    configured.seat_config = json!({"readiness":"complete"});
    host.register(configured.clone()).await.unwrap();
    let cursor = host.status("ready").await.unwrap()["sequence"]
        .as_u64()
        .unwrap();
    let mut events = host.subscribe("ready", cursor).unwrap();
    host.ensure_started("ready").await.unwrap();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        if event.event["type"] == "root_readiness" {
            break;
        }
    }
    assert_eq!(host.status("ready").await.unwrap()["available"], true);
    configured.seat_config = json!({"readiness":"memory_missing"});
    host.register(configured).await.unwrap();
    assert_eq!(host.status("ready").await.unwrap()["available"], false);
    host.ensure_started("ready").await.unwrap();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        if event.event["type"] == "root_readiness" {
            break;
        }
    }
    let status = host.status("ready").await.unwrap();
    assert_eq!(
        status["readiness"]["ready"], true,
        "fixture claims ready despite a missing component"
    );
    assert_eq!(
        status["available"], false,
        "the host independently verifies all required components"
    );
    host.shutdown().await;
    assert_eq!(host.status("ready").await.unwrap()["available"], false);
}

#[test]
fn real_native_readiness_shape_is_verified_and_failed_or_legacy_probes_are_not() {
    use proxy_node_server::agent_host::RuntimeReadiness;
    let mut event = json!({"ready":true,"agent_name":"Local test","checked_at":1791372309u64,
        "components":{"model":{"ready":true,"status":"inference_verified","usage":{"input":10,"output":2}},
        "mcp":{"ready":true,"status":"tools_verified","tools":2},
        "memory":{"ready":true,"status":"journal_and_optchat_open"},
        "memory_adapters":{"ready":true,"registered":["cognition"]},
        "life_map":{"ready":true,"required":false,"status":"not_required"}},"work_ahead":""});
    assert!(
        serde_json::from_value::<RuntimeReadiness>(event.clone())
            .unwrap()
            .verified()
    );
    event["components"]["model"]["ready"] = json!(false);
    assert!(
        !serde_json::from_value::<RuntimeReadiness>(event.clone())
            .unwrap()
            .verified()
    );
    event["components"]["model"]["ready"] = json!(true);
    event["components"]["mcp"]["status"] = json!("handshakes_complete");
    assert!(
        !serde_json::from_value::<RuntimeReadiness>(event)
            .unwrap()
            .verified()
    );
}

#[tokio::test]
async fn stopping_one_host_retains_accepted_work_and_stamps_logical_agent_identity() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let mut task = spec(temp.path(), "task-runtime");
    task.seat_config["agent_id"] = json!("dot");
    host.register(task).await.unwrap();
    host.register(spec(temp.path(), "sibling")).await.unwrap();
    host.ensure_started("sibling").await.unwrap();
    let sibling = host.status("sibling").await.unwrap()["pid"].clone();
    let mut events = host.subscribe("task-runtime", 0).unwrap();
    assert_eq!(
        host.submit("task-runtime", input("accepted-before-stop", "slow"))
            .await
            .unwrap()["durable"],
        true
    );
    host.stop("task-runtime").await.unwrap();
    host.stop("task-runtime").await.unwrap();
    assert_eq!(host.status("task-runtime").await.unwrap()["hosted"], false);
    assert_eq!(host.status("sibling").await.unwrap()["pid"], sibling);
    let wire: Value = serde_json::from_str(
        std::fs::read_to_string(temp.path().join("state/task-runtime/inputs"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(wire["agent_id"], "dot");
    host.ensure_started("task-runtime").await.unwrap();
    settled(&mut events, "accepted-before-stop").await;
    assert_eq!(
        std::fs::read_to_string(temp.path().join("state/task-runtime/inputs"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    host.shutdown().await;
}

#[tokio::test]
async fn unconfirmed_shell_cleanup_is_reported_when_a_process_stops() {
    let temp = tempfile::tempdir().unwrap();
    let host = AgentHost::open(temp.path().join("host")).unwrap();
    let mut configured = spec(temp.path(), "uncertain");
    configured.env.insert("REJECT_SHUTDOWN".into(), "1".into());
    host.register(configured).await.unwrap();
    let mut events = host.subscribe("uncertain", 0).unwrap();
    host.submit("uncertain", input("one", "ready"))
        .await
        .unwrap();
    settled(&mut events, "one").await;
    assert!(
        matches!(host.stop("uncertain").await,Err(HostError::Rejected(message)) if message.contains("without confirming shell cleanup"))
    );
    assert!(host.status("uncertain").await.unwrap()["pid"].is_null());
    assert!(
        std::fs::read_to_string(temp.path().join("host/uncertain/events.jsonl"))
            .unwrap()
            .contains("work outcome is unknown")
    );
    host.shutdown().await;
}
