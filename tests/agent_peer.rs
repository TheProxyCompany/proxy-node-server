#![cfg(feature = "agent-host")]
//! Protocol proof for `agent_host::peer`: real local HTTP round trips between
//! two independently generated trusted devices, an injected effect-counting
//! handler, and the full set of negative fixtures. The handler is a fixture —
//! passing these tests says nothing about real model execution.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proxy_node_server::DeviceId;
use proxy_node_server::agent_host::AgentInput;
use proxy_node_server::agent_host::peer::{
    DefinitionBundle, DefinitionFile, MAX_EVENTS, OUTCOME_UNKNOWN_STATUS, PROTOCOL_VERSION,
    PeerClient, PeerCommand, PeerEndpoint, PeerError, PeerServer, REPLY_STORE, REQUEST_STORE,
    ReplyPayload, RequestPayload, VerifiedRequest, frame_response, seal_payload,
};
use proxy_node_server::identity::DeviceIdentity;
use proxy_node_server::registry::DeviceRegistry;
use serde_json::{Value, json};

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

type Book = Arc<StdMutex<DeviceRegistry>>;

fn book(identities: &[&DeviceIdentity]) -> Book {
    let mut registry = DeviceRegistry::new();
    for identity in identities {
        registry.insert_sec1(&identity.public_key_sec1()).unwrap();
    }
    Arc::new(StdMutex::new(registry))
}

/// Build the exact framed body a `PeerClient` sends for one command so tests
/// can replay byte-identical signed envelopes.
fn framed(caller: &DeviceIdentity, target: DeviceId, command: PeerCommand) -> Vec<u8> {
    framed_at(caller, target, command, now_ms())
}

fn framed_at(
    caller: &DeviceIdentity,
    target: DeviceId,
    command: PeerCommand,
    timestamp_ms: u64,
) -> Vec<u8> {
    let request = RequestPayload {
        v: PROTOCOL_VERSION,
        target,
        timestamp_ms,
        command,
    };
    let envelope = seal_payload(REQUEST_STORE, &request, caller).unwrap();
    postcard::to_allocvec(&(
        envelope.to_bytes().unwrap(),
        postcard::to_allocvec(&request).unwrap(),
    ))
    .unwrap()
}

#[derive(Clone)]
struct RawPost {
    url: String,
}

impl RawPost {
    async fn send(&self, body: Vec<u8>) -> reqwest::Response {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await
            .unwrap()
    }
}

/// Shared, effect-counting handler state behind a plain closure handler.
struct Fixture {
    effects: AtomicUsize,
    installed: StdMutex<Vec<String>>,
}

impl Fixture {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            effects: AtomicUsize::new(0),
            installed: StdMutex::new(Vec::new()),
        })
    }
    fn effect_count(&self) -> usize {
        self.effects.load(Ordering::SeqCst)
    }
    fn installed(&self) -> Vec<String> {
        self.installed.lock().unwrap().clone()
    }

    fn handler(this: Arc<Self>) -> impl proxy_node_server::agent_host::peer::PeerHandler {
        move |request: VerifiedRequest| {
            let this = Arc::clone(&this);
            async move {
                this.effects.fetch_add(1, Ordering::SeqCst);
                let agent = request.command.agent_id().to_string();
                let sender = request.sender.to_hex();
                Ok::<Value, PeerError>(match request.command {
                    PeerCommand::Ensure { definitions, .. }
                    | PeerCommand::Attach { definitions, .. } => {
                        let digest = definitions
                            .as_ref()
                            .map(|bundle| {
                                bundle.verify_digest()?;
                                this.installed.lock().unwrap().push(bundle.digest.clone());
                                Ok::<_, PeerError>(bundle.digest.clone())
                            })
                            .transpose()?;
                        json!({
                            "agent": agent, "by": sender, "available": true,
                            "installed_digest": digest,
                        })
                    }
                    PeerCommand::Open { .. } => {
                        json!({"agent": agent, "by": sender, "attached": true})
                    }
                    PeerCommand::Status { .. } => {
                        json!({"agent": agent, "by": sender, "status": "idle", "sequence": 7})
                    }
                    PeerCommand::InputCursor { .. } => {
                        json!({"agent": agent, "by": sender, "sequence": 3})
                    }
                    PeerCommand::Submit { ref input, .. } => {
                        json!({
                            "agent": agent, "by": sender, "accepted": true,
                            "durable": true, "input_id": input.id,
                        })
                    }
                    PeerCommand::Events {
                        after_sequence,
                        limit,
                        ..
                    } => {
                        let events: Vec<Value> = (after_sequence + 1
                            ..=after_sequence + limit as u64)
                            .map(|sequence| json!({"sequence": sequence, "agent_id": agent}))
                            .collect();
                        json!({"agent": agent, "by": sender, "events": events})
                    }
                    PeerCommand::Abort { .. } | PeerCommand::AbortInput { .. } => {
                        json!({"agent": agent, "by": sender, "abort_requested": true})
                    }
                })
            }
        }
    }
}

struct Host {
    _temp: tempfile::TempDir,
    port: u16,
    identity: Arc<DeviceIdentity>,
    fixture: Arc<Fixture>,
    replay_dir: std::path::PathBuf,
    server: tokio::task::JoinHandle<()>,
}

impl Host {
    async fn boot(identity: Arc<DeviceIdentity>, trusted: Book, skew: Duration) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let replay_dir = temp.path().join("replay");
        Self::boot_in(temp, identity, trusted, skew, replay_dir).await
    }

    async fn boot_in(
        temp: tempfile::TempDir,
        identity: Arc<DeviceIdentity>,
        trusted: Book,
        skew: Duration,
        replay_dir: std::path::PathBuf,
    ) -> Self {
        let fixture = Fixture::new();
        let handler: Arc<dyn proxy_node_server::agent_host::peer::PeerHandler> =
            Arc::new(Fixture::handler(Arc::clone(&fixture)));
        let server =
            PeerServer::with_skew(Arc::clone(&identity), trusted, handler, &replay_dir, skew)
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let serve = tokio::spawn(async move {
            axum::serve(listener, server.router()).await.unwrap();
        });
        Host {
            _temp: temp,
            port,
            identity,
            fixture,
            replay_dir,
            server: serve,
        }
    }

    fn post(&self) -> RawPost {
        RawPost {
            url: format!("http://127.0.0.1:{}/peer/agents", self.port),
        }
    }

    fn client(&self, caller: Arc<DeviceIdentity>, book: Book) -> PeerClient<Book> {
        let endpoint = PeerEndpoint::new(&format!("http://127.0.0.1:{}", self.port)).unwrap();
        PeerClient::new(caller, book, self.identity.device_id(), endpoint).unwrap()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.server.abort();
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
        task_id: None,
    }
}

fn bundle(files: &[(&str, &str)]) -> DefinitionBundle {
    DefinitionBundle {
        files: files
            .iter()
            .map(|(path, content)| DefinitionFile {
                path: (*path).into(),
                content: (*content).into(),
            })
            .collect(),
        digest: String::new(),
        expected: None,
    }
    .seal()
    .unwrap()
}

#[test]
fn signed_round_trip_submit_and_exact_identity() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let client = host.client(Arc::clone(&caller), all);

        let accepted = client
            .command(PeerCommand::Submit {
                agent: "jarvis".into(),
                input: input("input-1", "hello mesh").into(),
            })
            .await
            .unwrap();
        assert_eq!(accepted["agent"], "jarvis");
        assert_eq!(accepted["by"], caller.device_id().to_hex());
        assert_eq!(accepted["input_id"], "input-1");
        assert_eq!(accepted["durable"], true);
        assert_eq!(host.fixture.effect_count(), 1);

        let open = client
            .command(PeerCommand::Open {
                agent: "jarvis".into(),
            })
            .await
            .unwrap();
        assert_eq!(open["attached"], true);
        assert_eq!(open["agent"], "jarvis");
        assert_eq!(host.fixture.effect_count(), 2);
    });
}

#[test]
fn events_are_bounded_and_correlated() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let client = host.client(caller, all);
        let reply = client
            .command(PeerCommand::Events {
                agent: "jarvis".into(),
                after_sequence: 3,
                limit: 4,
            })
            .await
            .unwrap();
        let events = reply["events"].as_array().unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0]["sequence"], 4);
        assert!(events.iter().all(|event| event["agent_id"] == "jarvis"));
    });
}

#[test]
fn replay_returns_cached_reply_without_second_effect_even_after_reopen() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let body = framed(
            &caller,
            target.device_id(),
            PeerCommand::Submit {
                agent: "jarvis".into(),
                input: input("input-1", "first").into(),
            },
        );

        // Durable replay state lives in its own directory so it outlives the
        // first host's tempdir (which is deleted when that host drops).
        let durable = tempfile::tempdir().unwrap();
        let replay_dir = durable.path().join("replay");

        let host = Host::boot_in(
            tempfile::tempdir().unwrap(),
            Arc::clone(&target),
            all.clone(),
            Duration::from_secs(120),
            replay_dir.clone(),
        )
        .await;
        let first = host.post().send(body.clone()).await;
        assert!(first.status().is_success());
        assert_eq!(host.fixture.effect_count(), 1);
        let first_bytes = first.bytes().await.unwrap().to_vec();

        // Identical captured bytes: cached reply, no second effect.
        let second = host.post().send(body.clone()).await;
        assert!(second.status().is_success());
        assert_eq!(host.fixture.effect_count(), 1);
        assert_eq!(second.bytes().await.unwrap().to_vec(), first_bytes);

        // Restart the server over the same durable replay directory. The old
        // listener's port release and the new listener's readiness are not
        // synchronous with `drop`, so poll until the reopened instance answers
        // before asserting on its effect counter.
        drop(host);
        let reopened = Host::boot_in(
            tempfile::tempdir().unwrap(),
            target,
            all,
            Duration::from_secs(120),
            replay_dir,
        )
        .await;
        let mut third = None;
        for _ in 0..50 {
            match reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_millis(500))
                .build()
                .unwrap()
                .post(format!("http://127.0.0.1:{}/peer/agents", reopened.port))
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) => {
                    third = Some(response);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let third = third.expect("reopened server did not answer");
        assert!(third.status().is_success());
        assert_eq!(reopened.fixture.effect_count(), 0);
        assert_eq!(third.bytes().await.unwrap().to_vec(), first_bytes);
    });
}

#[test]
fn unknown_sender_never_reaches_the_handler() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        // The server's book trusts only the target itself.
        let server_book = book(&[&target]);
        let host = Host::boot(Arc::clone(&target), server_book, Duration::from_secs(120)).await;
        let client = host.client(caller, all);
        let error = client
            .command(PeerCommand::Status {
                agent: "jarvis".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, PeerError::Transport(_)));
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn tampered_payload_breaks_the_signature_commit() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;

        // Valid envelope; payload changed after sealing without re-signing.
        let request = RequestPayload {
            v: PROTOCOL_VERSION,
            target: target.device_id(),
            timestamp_ms: now_ms(),
            command: PeerCommand::Status {
                agent: "jarvis".into(),
            },
        };
        let envelope = seal_payload(REQUEST_STORE, &request, &caller).unwrap();
        let tampered = RequestPayload {
            command: PeerCommand::Status {
                agent: "other".into(),
            },
            ..RequestPayload { ..request }
        };
        let body = postcard::to_allocvec(&(
            envelope.to_bytes().unwrap(),
            postcard::to_allocvec(&tampered).unwrap(),
        ))
        .unwrap();
        assert_eq!(
            host.post().send(body).await.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn forged_signer_is_rejected() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let attacker = DeviceIdentity::generate();
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        // Well-formed, validly signed envelope from a device the book does not
        // trust.
        let body = framed(
            &attacker,
            target.device_id(),
            PeerCommand::Status {
                agent: "jarvis".into(),
            },
        );
        assert_eq!(
            host.post().send(body).await.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn stale_request_is_rejected_by_freshness_window() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(2)).await;
        let body = framed_at(
            &caller,
            target.device_id(),
            PeerCommand::Status {
                agent: "jarvis".into(),
            },
            now_ms() - 10_000,
        );
        assert_eq!(
            host.post().send(body).await.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn misdirected_request_for_another_target_is_rejected() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let elsewhere = DeviceIdentity::generate();
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let body = framed(
            &caller,
            elsewhere.device_id(), // signed for the wrong recipient
            PeerCommand::Status {
                agent: "jarvis".into(),
            },
        );
        assert_eq!(
            host.post().send(body).await.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn interim_crash_reports_outcome_unknown_and_does_not_repeat_effect() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;

        // Write a bare Pending admission as the server would have before its
        // crash (byte 0 = Pending; there is no completed reply).
        let request = RequestPayload {
            v: PROTOCOL_VERSION,
            target: target.device_id(),
            timestamp_ms: now_ms(),
            command: PeerCommand::Submit {
                agent: "jarvis".into(),
                input: input("input-9", "crashy").into(),
            },
        };
        let envelope = seal_payload(REQUEST_STORE, &request, &caller).unwrap();
        let record = host
            .replay_dir
            .join(format!("{}.replay", envelope.id.to_hex()));
        std::fs::write(&record, [0u8]).unwrap();

        let body = postcard::to_allocvec(&(
            envelope.to_bytes().unwrap(),
            postcard::to_allocvec(&request).unwrap(),
        ))
        .unwrap();
        let response = host.post().send(body).await;
        assert_eq!(response.status(), OUTCOME_UNKNOWN_STATUS);
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn forged_reply_is_rejected_by_client() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let attacker = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);

        // Serve a reply signed by the attacker: bound to the request id, but
        // from the wrong peer.
        let app = axum::Router::new().route(
            "/peer/agents",
            axum::routing::post({
                let attacker = Arc::clone(&attacker);
                move |body: axum::body::Bytes| {
                    let attacker = Arc::clone(&attacker);
                    async move {
                        let (envelope_bytes, _payload): (Vec<u8>, Vec<u8>) =
                            postcard::from_bytes(&body).unwrap();
                        let request_envelope =
                            proxy_node_server::op::SignedOp::from_bytes(&envelope_bytes).unwrap();
                        let payload = ReplyPayload {
                            v: PROTOCOL_VERSION,
                            request_id: request_envelope.id,
                            requester: request_envelope.body.device,
                            error: None,
                            payload: Some(json!({"agent": "jarvis", "status": "forged"})),
                        };
                        let reply = seal_payload(REPLY_STORE, &payload, &attacker).unwrap();
                        frame_response(&reply, &payload).unwrap()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let endpoint = PeerEndpoint::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let client = PeerClient::new(caller, all, target.device_id(), endpoint).unwrap();
        let error = client
            .command(PeerCommand::Status {
                agent: "jarvis".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, PeerError::Unauthenticated));
        server.abort();
    });
}

#[test]
fn malformed_definition_traversal_is_rejected() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let client = host.client(Arc::clone(&caller), all);
        let mut traversal = bundle(&[("agents/jarvis.md", "ok")]);
        traversal.files[0].path = "../escape.md".into();
        traversal.digest = "AAAA".into(); // wrong for the traversal content
        let result = client
            .command(PeerCommand::Ensure {
                agent: "jarvis".into(),
                definitions: Some(traversal),
            })
            .await;
        assert!(matches!(result.unwrap_err(), PeerError::Invalid(_)));
        assert_eq!(host.fixture.effect_count(), 0);
        assert!(host.fixture.installed().is_empty());
    });
}

#[test]
fn definition_bundle_installs_as_data_with_digest_stamp() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let client = host.client(caller, all);
        let definitions = bundle(&[
            ("agents/jarvis.md", "# Jarvis\nhost a durable agent"),
            ("loadouts/deep-work.yaml", "model: kimi-k3"),
        ]);
        let reply = client
            .command(PeerCommand::Ensure {
                agent: "jarvis".into(),
                definitions: Some(definitions.clone()),
            })
            .await
            .unwrap();
        assert_eq!(reply["installed_digest"], json!(definitions.digest));
        assert_eq!(host.fixture.installed(), vec![definitions.digest]);
    });
}

#[test]
fn oversized_events_limit_is_rejected_client_side() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let client = host.client(caller, all);
        let result = client
            .command(PeerCommand::Events {
                agent: "jarvis".into(),
                after_sequence: 0,
                limit: MAX_EVENTS + 1,
            })
            .await;
        assert!(matches!(result.unwrap_err(), PeerError::Invalid(_)));
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn oversized_request_body_is_rejected() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let body = vec![0u8; proxy_node_server::agent_host::peer::MAX_BODY_BYTES + 1];
        let response = host.post().send(body).await;
        assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(host.fixture.effect_count(), 0);
    });
}

#[test]
fn concurrent_identical_bytes_run_the_handler_once() {
    // Two deliveries of the *same* signed bytes must not both pass the durable
    // get/admit gap. 64 simultaneous requests share one start barrier so the
    // window is exercised, not merely approached.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);
        let host = Host::boot(Arc::clone(&target), all.clone(), Duration::from_secs(120)).await;
        let body = framed(
            &caller,
            target.device_id(),
            PeerCommand::Submit {
                agent: "jarvis".into(),
                input: input("input-race", "same bytes").into(),
            },
        );
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .build()
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(64));
        let mut handles = Vec::new();
        for _ in 0..64 {
            let client = client.clone();
            let url = format!("http://127.0.0.1:{}/peer/agents", host.port);
            let body = body.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                client.post(url).body(body).send().await.unwrap().status()
            }));
        }
        for handle in handles {
            let _ = handle.await.unwrap();
        }
        assert_eq!(
            host.fixture.effect_count(),
            1,
            "identical signed bytes ran the handler more than once"
        );
    });
}

#[test]
fn oversized_reply_is_rejected_while_streaming() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);

        // A reply body one byte over the client's read cap, and not even a
        // well-formed frame: the size bound must reject it before parsing.
        let oversized =
            vec![0u8; (proxy_node_server::agent_host::peer::MAX_RESPONSE_BYTES + 1) as usize];
        let app = axum::Router::new().route(
            "/peer/agents",
            axum::routing::post(move || {
                let oversized = oversized.clone();
                async move { oversized }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let endpoint = PeerEndpoint::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let client = PeerClient::new(caller, all, target.device_id(), endpoint).unwrap();
        let error = client
            .command(PeerCommand::Status {
                agent: "jarvis".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, PeerError::Invalid(_)), "got {error:?}");
        server.abort();
    });
}

#[test]
fn tampered_reply_from_the_correct_target_is_rejected() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);

        // The reply is correctly signed by the *expected target*, bound to the
        // request id and requester, but the payload bytes the client receives
        // differ from the ones that were signed. The digest commit must catch it.
        let app = axum::Router::new().route(
            "/peer/agents",
            axum::routing::post({
                let target = Arc::clone(&target);
                move |body: axum::body::Bytes| {
                    let target = Arc::clone(&target);
                    async move {
                        let (envelope_bytes, _payload): (Vec<u8>, Vec<u8>) =
                            postcard::from_bytes(&body).unwrap();
                        let request_envelope =
                            proxy_node_server::op::SignedOp::from_bytes(&envelope_bytes).unwrap();
                        let signed = ReplyPayload {
                            v: PROTOCOL_VERSION,
                            request_id: request_envelope.id,
                            requester: request_envelope.body.device,
                            error: None,
                            payload: Some(json!({"agent": "jarvis", "status": "ok"})),
                        };
                        let reply = seal_payload(REPLY_STORE, &signed, &target).unwrap();
                        let tampered = ReplyPayload {
                            payload: Some(json!({"agent": "jarvis", "status": "tampered"})),
                            ..signed
                        };
                        frame_response(&reply, &tampered).unwrap()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let endpoint = PeerEndpoint::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let client = PeerClient::new(caller, all, target.device_id(), endpoint).unwrap();
        let error = client
            .command(PeerCommand::Status {
                agent: "jarvis".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, PeerError::Unauthenticated), "got {error:?}");
        server.abort();
    });
}

#[test]
fn wrong_request_id_reply_is_rejected() {
    runtime().block_on(async {
        let caller = Arc::new(DeviceIdentity::generate());
        let target = Arc::new(DeviceIdentity::generate());
        let all = book(&[&caller, &target]);

        // Validly signed by the expected target, addressed to this requester,
        // but bound to a *different* request id: a replayed or mismatched reply
        // must never be surfaced as the answer to this request.
        let app = axum::Router::new().route(
            "/peer/agents",
            axum::routing::post({
                let target = Arc::clone(&target);
                move |body: axum::body::Bytes| {
                    let target = Arc::clone(&target);
                    async move {
                        let (_envelope_bytes, _payload): (Vec<u8>, Vec<u8>) =
                            postcard::from_bytes(&body).unwrap();
                        let payload = ReplyPayload {
                            v: PROTOCOL_VERSION,
                            request_id: proxy_node_server::op::OpId::from_bytes([9u8; 32]),
                            requester: caller_device(&body),
                            error: None,
                            payload: Some(json!({"agent": "jarvis", "status": "stale"})),
                        };
                        let reply = seal_payload(REPLY_STORE, &payload, &target).unwrap();
                        frame_response(&reply, &payload).unwrap()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let endpoint = PeerEndpoint::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let client = PeerClient::new(caller, all, target.device_id(), endpoint).unwrap();
        let error = client
            .command(PeerCommand::Status {
                agent: "jarvis".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, PeerError::Unauthenticated), "got {error:?}");
        server.abort();
    });
}

fn caller_device(body: &axum::body::Bytes) -> DeviceId {
    let (envelope_bytes, _payload): (Vec<u8>, Vec<u8>) = postcard::from_bytes(body).unwrap();
    proxy_node_server::op::SignedOp::from_bytes(&envelope_bytes)
        .unwrap()
        .body
        .device
}
