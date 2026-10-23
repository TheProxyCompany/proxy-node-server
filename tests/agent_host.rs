#![cfg(feature = "agent-host")]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use proxy_node_server::agent_host::http::{HostOperation, router};
use proxy_node_server::agent_host::{AgentHost, AgentSpec, HostError, WorkspaceMode};
use serde_json::{Value, json};

fn spec(root: &Path, id: &str) -> AgentSpec {
    AgentSpec {
        id: id.into(),
        display_name: None,
        command: "/bin/sh".into(),
        args: vec![],
        agent_dir: root.join("identity"),
        state_dir: root.join("state").join(id),
        workspace: root.into(),
        workspace_mode: WorkspaceMode::Host,
        seat_config: json!({}),
        space: None,
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn http_requires_the_exact_agent_grant() {
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
        .get(format!("{base}/client/agents/dot/status"))
        .bearer_auth("dot-only")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(host.status("dot").await.unwrap()["hosted"], false);
    host.shutdown().await;
    server.abort();
}

#[test]
fn one_provisioner_owns_the_registry_until_it_closes() {
    use proxy_node_server::agent_host::space::CuaSpaceManager;
    let temp = tempfile::tempdir().unwrap();
    let first = CuaSpaceManager::open("/bin/sh", temp.path()).unwrap();
    assert!(matches!(
        CuaSpaceManager::open("/bin/sh", temp.path()),
        Err(HostError::Busy)
    ));
    drop(first);
    CuaSpaceManager::open("/bin/sh", temp.path()).unwrap();
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
