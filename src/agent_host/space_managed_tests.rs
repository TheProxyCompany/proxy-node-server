use super::super::{
    CreationState, CuaSpaceManager, HostError, Ownership, SpaceResources, run_command,
};
use super::macos;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::process::Command;

struct Fixture {
    _directory: tempfile::TempDir,
    home: PathBuf,
    root: PathBuf,
    binary: PathBuf,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    fn new() -> Self {
        // Short physical Unix socket paths, independent of the real Cua home.
        let directory = tempfile::TempDir::new_in("/tmp").unwrap();
        let home = directory.path().canonicalize().unwrap().join("home");
        let root = home.join("runtimes/linux");
        for path in [
            root.join("vm/_lima/colima-cua"),
            root.join("vm/_lima/_disks/colima-cua"),
            root.join("vm/cua"),
            root.join("home"),
            root.join("colima-0.10.3-lima-2.2.0/bin"),
            root.join("colima-0.10.3-lima-2.2.0/lima/bin"),
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        for (file, content) in [
            (
                "vm/_lima/colima-cua/lima.yaml",
                "cpus: 3\nmemory: 4294967296\n",
            ),
            ("vm/cua/colima.yaml", "cpu: 3\nmemory: 4\n"),
            ("vm/_lima/colima-cua/disk", "existing guest data"),
            (
                "vm/_lima/_disks/colima-cua/datadisk",
                "existing container workspaces",
            ),
            (
                "colima-0.10.3-lima-2.2.0/.verified",
                "colima 0.10.3\nlima 2.2.0\n",
            ),
            (
                "colima-0.10.3-lima-2.2.0/lima/bin/limactl",
                "fixture, never invoked",
            ),
        ] {
            std::fs::write(root.join(file), content).unwrap();
        }
        executable(
            &root.join("colima-0.10.3-lima-2.2.0/bin/colima"),
            r#"#!/usr/bin/python3
import json, os, pathlib, sys, time
root = pathlib.Path(os.environ['COLIMA_HOME']).parent
with (root / 'boot-calls.jsonl').open('a') as out:
    out.write(json.dumps({'args':sys.argv[1:], 'env':dict(os.environ), 'pid':os.getpid()}) + '\n')
if (root / 'boot-fail').exists():
    print('fixture managed runtime boot failed', file=sys.stderr)
    sys.exit(23)
if (root / 'boot-delay').exists():
    time.sleep(float((root / 'boot-delay').read_text()))
if not (root / 'boot-no-socket').exists():
    (root / 'start-socket').write_text('ready')
"#,
        );
        let binary = home.join("cua-fixture");
        executable(
            &binary,
            r#"#!/usr/bin/python3
import json, os, pathlib, sys
home = pathlib.Path(os.environ['CUA_HOME'])
args = sys.argv[sys.argv.index('--json') + 1:]
with (home / 'cua-calls.jsonl').open('a') as out:
    out.write(json.dumps(args) + '\n')
registry = json.loads((home / 'registry.json').read_text())
if args == ['runtime', 'doctor']:
    selected = not (home / 'system-engine').exists()
    ready = selected and (home / 'runtimes/linux/vm/cua/docker.sock').exists()
    print(json.dumps({'backends':[{'backend':'managed', 'ready':ready, 'provisionable':selected and not ready}]}))
elif args[:2] == ['sb', 'ls']:
    if (home / 'invalid-list').exists():
        print('{}')
        sys.exit(0)
    print(json.dumps(list(registry.values())))
elif args[:2] == ['sb', 'info']:
    print(json.dumps(registry[args[2]]))
elif args[:2] == ['spaces', 'start']:
    if not (home / 'runtimes/linux/vm/cua/docker.sock').exists():
        print('local runtime: instance not found', file=sys.stderr)
        sys.exit(1)
    item = registry[args[2]]
    item['state'], item['status'] = 'running', 'ready'
    (home / 'registry.json').write_text(json.dumps(registry))
    print(json.dumps({'state':'running'}))
elif args[:2] == ['spaces', 'create']:
    if (home / 'create-fail').exists():
        print('fixture initial create failed', file=sys.stderr)
        sys.exit(23)
    name = args[args.index('--name') + 1]
    identity = 'local:' + name
    if identity in registry:
        print('existing guest cannot be replaced', file=sys.stderr)
        sys.exit(24)
    registry[identity] = {'id':identity,'name':name,'location':'local','kind':'container','state':'running','status':'ready','container_id':'new-reserved-container','created_at':'2026-10-08T00:00:00Z','endpoints':{'env':'http://127.0.0.1:33331'}}
    (home / 'registry.json').write_text(json.dumps(registry))
    print(json.dumps({'state':'running'}))
elif args[:2] == ['sb', 'exec']:
    print(json.dumps({'exit_code':0, 'stdout':'/home/agent\n' if args[3] == 'printenv HOME' else ''}))
else:
    print('unexpected mutation: ' + repr(args), file=sys.stderr)
    sys.exit(99)
"#,
        );
        std::fs::write(home.join("registry.json"), "{}").unwrap();
        let runtime = root.clone();
        let server = tokio::spawn(async move {
            while !runtime.join("start-socket").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let listener = UnixListener::bind(runtime.join("vm/cua/docker.sock")).unwrap();
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = Vec::new();
                while request.len() < 1024 && !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                }
                if request.starts_with(b"GET /_ping HTTP/1.1\r\n") {
                    let response: &[u8] = if runtime.join("unhealthy-engine").exists() {
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    };
                    let _ = stream.write_all(response).await;
                    let _ = stream.shutdown().await;
                }
            }
        });
        Self {
            _directory: directory,
            home,
            root,
            binary,
            server,
        }
    }
    fn manager(&self, name: &str) -> CuaSpaceManager {
        let mut manager =
            CuaSpaceManager::open(&self.binary, self.home.join(format!("profile-{name}"))).unwrap();
        // Exercise the real shared provisioning lock against the test engine.
        manager.home = self.home.clone();
        manager
    }
    fn guest(&self, manager: &CuaSpaceManager, agent: &str, owned: bool) -> String {
        let name = CuaSpaceManager::name(&manager.namespace, agent);
        let id = format!("local:{name}");
        let mut registry: Value =
            serde_json::from_slice(&std::fs::read(self.home.join("registry.json")).unwrap())
                .unwrap();
        registry[&id] = json!({"id":id,"name":name,"location":"local","kind":"container","state":"stopped","status":"stopped","container_id":format!("original-{agent}"),"created_at":"2026-10-01T00:00:00Z","endpoints":{"env":"http://127.0.0.1:33331"}});
        std::fs::write(
            self.home.join("registry.json"),
            serde_json::to_vec(&registry).unwrap(),
        )
        .unwrap();
        if owned {
            std::fs::write(
                manager.receipt(agent),
                serde_json::to_vec(&Ownership {
                    version: 1,
                    agent_id: agent.into(),
                    name,
                    resources: SpaceResources::default(),
                    creation: None,
                    binding: None,
                })
                .unwrap(),
            )
            .unwrap();
        }
        id
    }
    fn protected(&self) -> Vec<Vec<u8>> {
        [
            "vm/_lima/colima-cua/lima.yaml",
            "vm/cua/colima.yaml",
            "vm/_lima/colima-cua/disk",
            "vm/_lima/_disks/colima-cua/datadisk",
        ]
        .map(|p| std::fs::read(self.root.join(p)).unwrap())
        .into()
    }
    fn admitted_binding(&self, agent: &str, binding: &super::super::SpaceBinding) -> PathBuf {
        let state = self.home.join(format!("state-{agent}"));
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("inbox.jsonl"), format!("{}\n", json!({"kind":"input","input":{"id":"admitted","_authority":{"space":binding,"workspace":binding.workspace_root}}}))).unwrap();
        state
    }
    fn boots(&self) -> Vec<Value> {
        lines(&self.root.join("boot-calls.jsonl"))
    }
    fn commands(&self) -> Vec<Value> {
        lines(&self.home.join("cua-calls.jsonl"))
    }
    async fn make_running(&self) {
        std::fs::write(self.root.join("start-socket"), "ready").unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while tokio::net::UnixStream::connect(self.root.join("vm/cua/docker.sock"))
                .await
                .is_err()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn executable(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn reboot_restores_the_same_guest_after_booting_only_its_existing_runtime() {
    let fixture = Fixture::new();
    let manager = fixture.manager("one");
    let id = fixture.guest(&manager, "agent-a", true);
    let protected = fixture.protected();
    assert!(
        manager
            .recorded_binding("agent-a", &fixture.home.join("absent-state"))
            .unwrap()
            .is_none()
    );
    let binding = super::super::SpaceBinding {
        space_id: id.clone(),
        isolation: super::super::SpaceIsolation::Container,
        workspace_root: Some(PathBuf::from("/home/agent/ProxyWorkspace")),
        endpoint: Some("http://127.0.0.1:33331".into()),
    };
    let state = fixture.admitted_binding("agent-a", &binding);
    assert_eq!(
        manager.recorded_binding("agent-a", &state).unwrap(),
        Some(binding)
    );
    assert!(fixture.commands().is_empty());
    let space = manager
        .ensure_agent_space("agent-a", SpaceResources::default())
        .await
        .unwrap();
    assert_eq!(space.binding.space_id, id);
    assert_eq!(
        space.binding.workspace_root.as_deref(),
        Some(Path::new("/home/agent/ProxyWorkspace"))
    );
    assert_eq!(protected, fixture.protected());
    let registry: Value =
        serde_json::from_slice(&std::fs::read(fixture.home.join("registry.json")).unwrap())
            .unwrap();
    assert_eq!(registry[&id]["container_id"], "original-agent-a");
    assert_eq!(registry[&id]["created_at"], "2026-10-01T00:00:00Z");
    let boots = fixture.boots();
    assert_eq!(boots.len(), 1);
    assert_eq!(boots[0]["args"], json!(["--profile", "cua", "start"]));
    for (key, expected) in [
        ("HOME", fixture.root.join("home")),
        ("COLIMA_HOME", fixture.root.join("vm")),
        ("LIMA_HOME", fixture.root.join("vm/_lima")),
        ("DOCKER_CONFIG", fixture.root.join("home/.docker")),
    ] {
        assert_eq!(boots[0]["env"][key], expected.to_str().unwrap());
    }
    for key in [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "CUA_DAEMON",
        "PROXY_AGENT_API_KEY",
        "PROXY_HARNESS_API_KEY",
    ] {
        assert!(boots[0]["env"].get(key).is_none());
    }
    assert!(
        fixture
            .commands()
            .iter()
            .all(|args| !matches!(args[1].as_str(), Some("create" | "delete" | "stop")))
    );
}

#[tokio::test]
async fn a_running_runtime_never_invokes_boot_or_changes_its_profile() {
    let fixture = Fixture::new();
    fixture.make_running().await;
    let protected = fixture.protected();
    macos::ensure(
        &fixture.home,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(fixture.boots().is_empty());
    assert_eq!(protected, fixture.protected());
}

#[tokio::test]
async fn ownership_and_resource_validation_precede_any_runtime_boot() {
    let fixture = Fixture::new();
    let manager = fixture.manager("one");
    fixture.guest(&manager, "agent-a", false);
    assert!(matches!(
        manager
            .ensure_agent_space("agent-a", SpaceResources::default())
            .await,
        Err(HostError::Forbidden)
    ));
    assert!(fixture.boots().is_empty());
    assert!(!manager.receipt("agent-a").exists());
    fixture.guest(&manager, "agent-a", true);
    let owner = std::fs::read(manager.receipt("agent-a")).unwrap();
    let resources = SpaceResources {
        cpus: 3,
        ..SpaceResources::default()
    };
    assert!(
        manager
            .ensure_agent_space("agent-a", resources)
            .await
            .is_err()
    );
    assert_eq!(owner, std::fs::read(manager.receipt("agent-a")).unwrap());
    assert!(fixture.boots().is_empty());
    std::fs::write(manager.receipt("agent-a"), br#"{"version":1,"agent_id":"another-agent","name":"bad","resources":{"kind":"linux_container","cpus":2,"memory_mb":4096,"disk_gb":0}}"#).unwrap();
    assert!(
        manager
            .ensure_agent_space("agent-a", SpaceResources::default())
            .await
            .is_err()
    );
    assert!(fixture.boots().is_empty());
}

#[tokio::test]
async fn boot_failure_preserves_every_guest_and_does_not_recreate_or_force_stop() {
    let fixture = Fixture::new();
    let manager = fixture.manager("one");
    fixture.guest(&manager, "agent-a", true);
    let protected = fixture.protected();
    let registry = std::fs::read(fixture.home.join("registry.json")).unwrap();
    std::fs::write(fixture.root.join("boot-fail"), "fail").unwrap();
    let error = manager
        .ensure_agent_space("agent-a", SpaceResources::default())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fixture managed runtime boot failed"),
        "{error}"
    );
    assert_eq!(fixture.boots().len(), 1);
    assert_eq!(fixture.commands(), vec![json!(["runtime", "doctor"])]);
    assert_eq!(protected, fixture.protected());
    assert_eq!(
        registry,
        std::fs::read(fixture.home.join("registry.json")).unwrap()
    );
}

#[tokio::test]
async fn a_missing_owned_guest_after_boot_is_preserved_for_explicit_recovery() {
    let fixture = Fixture::new();
    let manager = fixture.manager("one");
    fixture.guest(&manager, "agent-a", true);
    std::fs::write(fixture.home.join("registry.json"), "{}").unwrap();
    let owner = std::fs::read(manager.receipt("agent-a")).unwrap();
    let error = manager
        .ensure_agent_space("agent-a", SpaceResources::default())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("owned Cua guest is missing"),
        "{error}"
    );
    assert_eq!(owner, std::fs::read(manager.receipt("agent-a")).unwrap());
    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(fixture.commands()[1][0], "sb");
    assert_eq!(fixture.commands()[1][1], "ls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_profiles_share_one_boot_and_keep_distinct_guest_identities() {
    let fixture = Fixture::new();
    let first = fixture.manager("one");
    let second = fixture.manager("two");
    let a = fixture.guest(&first, "agent-a", true);
    let b = fixture.guest(&second, "agent-b", true);
    std::fs::write(fixture.root.join("boot-delay"), "0.15").unwrap();
    let (a_result, b_result) = tokio::join!(
        first.ensure_agent_space("agent-a", SpaceResources::default()),
        second.ensure_agent_space("agent-b", SpaceResources::default())
    );
    assert_eq!(a_result.unwrap().binding.space_id, a);
    assert_eq!(b_result.unwrap().binding.space_id, b);
    assert_ne!(a, b);
    assert_eq!(fixture.boots().len(), 1);
    assert_eq!(
        fixture
            .commands()
            .iter()
            .filter(|args| args[0] == "spaces" && args[1] == "start")
            .count(),
        2
    );
}

#[tokio::test]
async fn unexpected_pins_or_symlinked_assets_never_boot() {
    let fixture = Fixture::new();
    let pin = fixture.root.join("colima-0.10.3-lima-2.2.0/.verified");
    std::fs::write(&pin, "different pin").unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    std::fs::write(&pin, "colima 0.10.3\nlima 2.2.0\n").unwrap();
    let asset = fixture.root.join("vm/cua/colima.yaml");
    std::fs::remove_file(&asset).unwrap();
    std::os::unix::fs::symlink(fixture.root.join("vm/_lima/colima-cua/lima.yaml"), asset).unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    assert!(fixture.boots().is_empty());
}

#[tokio::test]
async fn a_missing_or_empty_vm_disk_never_initializes_a_replacement() {
    let fixture = Fixture::new();
    let disk = fixture.root.join("vm/_lima/colima-cua/disk");
    std::fs::remove_file(&disk).unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    std::fs::write(&disk, "").unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    assert!(fixture.boots().is_empty());
    assert_eq!(std::fs::metadata(disk).unwrap().len(), 0);
}

#[tokio::test]
async fn a_missing_or_empty_container_data_disk_never_gets_created_or_formatted() {
    let fixture = Fixture::new();
    let disk = fixture.root.join("vm/_lima/_disks/colima-cua/datadisk");
    std::fs::remove_file(&disk).unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    std::fs::write(&disk, "").unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    assert!(fixture.boots().is_empty());
    assert_eq!(std::fs::metadata(disk).unwrap().len(), 0);
}

#[tokio::test]
async fn an_exit_zero_structured_failure_is_not_reported_as_success() {
    let mut command = Command::new("/usr/bin/printf");
    command.args([
        "%s",
        r#"[{"name":"runsc","status":"Error","detail":"unattended runsc install is unsupported"}]"#,
    ]);
    let error = run_command(command, Duration::from_secs(1), "fixture setup")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unattended runsc install is unsupported"),
        "{error}"
    );
}

#[tokio::test]
async fn successful_boot_without_a_reachable_engine_is_not_ready() {
    let fixture = Fixture::new();
    executable(
        &fixture.root.join("colima-0.10.3-lima-2.2.0/bin/colima"),
        r#"#!/bin/sh
printf '{"pid":%s}\n' "$$" >> "$COLIMA_HOME/../boot-calls.jsonl"
"#,
    );
    // Check health after the boot command exits; boot timeout has its own test.
    let error = macos::ensure(
        &fixture.home,
        Duration::from_secs(5),
        Duration::from_millis(20),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("engine did not become reachable"),
        "{error}"
    );
    assert_eq!(fixture.boots().len(), 1);
}

#[tokio::test]
async fn an_explicit_system_engine_does_not_boot_an_unused_managed_vm() {
    let fixture = Fixture::new();
    let manager = fixture.manager("one");
    fixture.guest(&manager, "agent-a", true);
    std::fs::write(fixture.home.join("system-engine"), "system").unwrap();
    assert!(
        manager
            .ensure_agent_space("agent-a", SpaceResources::default())
            .await
            .is_err()
    );
    assert!(fixture.boots().is_empty());
}

#[tokio::test]
async fn a_boot_timeout_reaps_its_command_without_force_stopping_the_runtime() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("boot-delay"), "10").unwrap();
    let error = macos::ensure(
        &fixture.home,
        Duration::from_secs(2),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error}");
    let boots = fixture.boots();
    assert_eq!(boots.len(), 1);
    let pid = boots[0]["pid"].as_u64().unwrap().to_string();
    let status = Command::new("/bin/kill")
        .args(["-0", &pid])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(!status.success(), "Timed-out bootstrap command survived");
    assert!(!fixture.root.join("start-socket").exists());
}

#[tokio::test]
async fn a_socket_accepting_connections_without_docker_health_is_not_ready() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("unhealthy-engine"), "unhealthy").unwrap();
    fixture.make_running().await;
    let error = macos::ensure(
        &fixture.home,
        Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("engine did not become reachable"),
        "{error}"
    );
    assert_eq!(fixture.boots().len(), 1);
}

#[tokio::test]
async fn isolated_docker_directory_and_nested_config_cannot_escape_by_symlink() {
    let fixture = Fixture::new();
    let external = fixture.home.join("unrelated-docker");
    std::fs::create_dir(&external).unwrap();
    std::fs::write(external.join("config.json"), "unchanged user config").unwrap();
    let isolated = fixture.root.join("home/.docker");
    std::os::unix::fs::symlink(&external, &isolated).unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    std::fs::remove_file(&isolated).unwrap();
    std::fs::create_dir(&isolated).unwrap();
    std::os::unix::fs::symlink(external.join("config.json"), isolated.join("config.json")).unwrap();
    assert!(
        macos::ensure(
            &fixture.home,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(external.join("config.json")).unwrap(),
        "unchanged user config"
    );
    assert!(fixture.boots().is_empty());
}

#[test]
fn captured_doctor_shape_preserves_the_selected_managed_backend() {
    let mut report: Value =
        serde_json::from_str(include_str!("space_managed_doctor_fixture.json")).unwrap();
    assert!(super::managed_selected(&report).unwrap());
    assert!(super::super::structured_failure(&report).is_none());
    let index = report["backends"]
        .as_array()
        .unwrap()
        .iter()
        .position(|backend| backend["backend"] == "managed")
        .unwrap();
    report["backends"][index]["ready"] = json!(false);
    report["backends"][index]["provisionable"] = json!(true);
    report["backends"][index]["provisioning"] = json!(["boot its VM"]);
    assert!(super::managed_selected(&report).unwrap());
    report["backends"][index]["provisionable"] = json!(false);
    assert!(!super::managed_selected(&report).unwrap());
    report["backends"][index]["ready"] = json!("false");
    assert!(super::managed_selected(&report).is_err());
}

#[tokio::test]
async fn a_reservation_adopts_its_existing_guest_only_after_same_id_binding() {
    let fixture = Fixture::new();
    fixture.make_running().await;
    let manager = fixture.manager("one");
    let id = fixture.guest(&manager, "agent-a", true);
    let mut owner = manager.load_owner("agent-a").unwrap();
    owner.version = 2;
    owner.creation = Some(CreationState::Reserved);
    std::fs::write(
        manager.receipt("agent-a"),
        serde_json::to_vec(&owner).unwrap(),
    )
    .unwrap();
    let path = fixture.home.join("registry.json");
    let mut registry: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    registry[&id]["id"] = json!("local:another-guest");
    std::fs::write(&path, serde_json::to_vec(&registry).unwrap()).unwrap();
    assert!(
        manager
            .ensure_agent_space("agent-a", SpaceResources::default())
            .await
            .is_err()
    );
    assert!(manager.load_owner("agent-a").unwrap().reserved());
    registry[&id]["id"] = json!(id);
    std::fs::write(&path, serde_json::to_vec(&registry).unwrap()).unwrap();
    assert_eq!(
        manager
            .ensure_agent_space("agent-a", SpaceResources::default())
            .await
            .unwrap()
            .binding
            .space_id,
        id
    );
    assert_eq!(
        manager.load_owner("agent-a").unwrap().creation,
        Some(CreationState::Established)
    );
    let registry: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(registry[&id]["container_id"], "original-agent-a");
    assert!(
        !fixture
            .commands()
            .iter()
            .any(|args| args[0] == "spaces" && args[1] == "create")
    );
}

#[tokio::test]
async fn a_reservation_never_creates_again_when_backend_or_absence_is_ambiguous() {
    for failure in ["system-engine", "invalid-list"] {
        let fixture = Fixture::new();
        fixture.make_running().await;
        let manager = fixture.manager("one");
        fixture.guest(&manager, "agent-a", true);
        let mut owner = manager.load_owner("agent-a").unwrap();
        owner.version = 2;
        owner.creation = Some(CreationState::Reserved);
        let bytes = serde_json::to_vec(&owner).unwrap();
        std::fs::write(manager.receipt("agent-a"), &bytes).unwrap();
        std::fs::write(fixture.home.join("registry.json"), "{}").unwrap();
        std::fs::write(fixture.home.join(failure), "unavailable").unwrap();
        assert!(
            manager
                .ensure_agent_space("agent-a", SpaceResources::default())
                .await
                .is_err(),
            "{failure}"
        );
        assert_eq!(std::fs::read(manager.receipt("agent-a")).unwrap(), bytes);
        assert!(
            !fixture
                .commands()
                .iter()
                .any(|args| args[0] == "spaces" && args[1] == "create")
        );
    }
}
