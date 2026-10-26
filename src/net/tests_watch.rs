use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;

use super::tests_support::{
    V1OnlyLog, seal_kv_op, spawn_app, spawn_watch_node, spawn_watch_node_with_limit,
};
use super::{
    DEFAULT_MAX_PARKED_WATCHES, HttpPullSource, RelayCursorV2, ServeState, WATCH_EMPTY_BACKOFF,
    load_relay_cursor, relay_router, router, save_relay_cursor, sync_relay_once_v2,
};
use crate::durable::OplogWriter;
use crate::error::TransportError;
use crate::hlc::{Hlc, NodeClock};
use crate::identity::DeviceIdentity;
use crate::kv::KvStore;
use crate::log::OpLog;
use crate::op::OrderKey;
use crate::registry::DeviceRegistry;

#[tokio::test]
async fn v1_only_log_keeps_v1_routes_and_reports_v2_not_implemented() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let op = seal_kv_op(&author, Hlc(10), "k", b"v");
    let expected_head = op.order_key();
    let log = Arc::new(Mutex::new(OpLog::new()));
    log.lock().unwrap().append(op);
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*author.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        V1OnlyLog(log),
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    assert_eq!(client.fetch_head().await.unwrap(), expected_head);
    let error = client
        .fetch_relay_ops_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2::START,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::RelayV2Unsupported { status: 501 }
    ));
}

#[tokio::test]
async fn relay_router_does_not_mount_legacy_log_routes() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*caller.verifying_key());
    let client = spawn_app(relay_router(ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    let legacy = client.fetch_head().await.unwrap_err();
    assert!(matches!(legacy, TransportError::Http(message) if message == "status 404 Not Found"));
    let relay = client
        .fetch_relay_head_v2(
            &caller,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2::START,
        )
        .await
        .unwrap();
    assert_eq!(relay.head, 0);
}

#[tokio::test]
async fn relay_sync_delivers_a_late_lower_semantic_op() {
    let remote = Arc::new(DeviceIdentity::generate());
    let local = DeviceIdentity::generate();
    let high = seal_kv_op(&remote, Hlc(30), "high", b"first");
    let low = seal_kv_op(&remote, Hlc(10), "low", b"late");
    assert!(low.order_key() < high.order_key());

    let remote_log = Arc::new(Mutex::new(OpLog::new()));
    remote_log.lock().unwrap().append(high.clone());
    let mut remote_registry = DeviceRegistry::new();
    remote_registry.insert_key(*remote.verifying_key());
    remote_registry.insert_key(*local.verifying_key());
    let source = spawn_app(relay_router(ServeState::new(
        Arc::clone(&remote),
        Arc::clone(&remote_log),
        Arc::new(Mutex::new(remote_registry)),
    )))
    .await;

    let mut local_registry = DeviceRegistry::new();
    local_registry.insert_key(*local.verifying_key());
    local_registry.insert_key(*remote.verifying_key());
    let local_registry = Mutex::new(local_registry);
    let clock = NodeClock::new(&local.device_id());
    let local_log = Mutex::new(OpLog::new());
    let store = Mutex::new(KvStore::new());
    let dir = tempfile::tempdir().unwrap();
    let writer = Mutex::new(OplogWriter::open(&dir.path().join("oplog")).unwrap());
    let mut cursor = RelayCursorV2::START;

    let first = sync_relay_once_v2(
        &source,
        &local,
        remote.device_id(),
        &remote.public_key_sec1(),
        &local_registry,
        &clock,
        &local_log,
        &store,
        &mut cursor,
        Some(&writer),
    )
    .await
    .unwrap();
    assert_eq!(first.received, 1);
    assert_eq!(first.appended, 1);
    assert_eq!(cursor.after, 1);

    remote_log.lock().unwrap().append(low.clone());
    let late = sync_relay_once_v2(
        &source,
        &local,
        remote.device_id(),
        &remote.public_key_sec1(),
        &local_registry,
        &clock,
        &local_log,
        &store,
        &mut cursor,
        Some(&writer),
    )
    .await
    .unwrap();

    assert_eq!(late.received, 1);
    assert_eq!(late.appended, 1);
    assert_eq!(cursor.after, 2);
    assert!(local_log.lock().unwrap().contains(&high.id));
    assert!(local_log.lock().unwrap().contains(&low.id));
    assert_eq!(store.lock().unwrap().get("high"), Some(&b"first"[..]));
    assert_eq!(store.lock().unwrap().get("low"), Some(&b"late"[..]));
}

#[tokio::test]
async fn relay_sync_authenticates_epoch_reset_and_replays_from_zero() {
    let remote = Arc::new(DeviceIdentity::generate());
    let local = DeviceIdentity::generate();
    let old = seal_kv_op(&remote, Hlc(10), "old", b"one");
    let new = seal_kv_op(&remote, Hlc(20), "new", b"two");

    let first_remote_log = Arc::new(Mutex::new(OpLog::new()));
    first_remote_log.lock().unwrap().append(old.clone());
    let mut first_remote_registry = DeviceRegistry::new();
    first_remote_registry.insert_key(*remote.verifying_key());
    first_remote_registry.insert_key(*local.verifying_key());
    let first_source = spawn_app(relay_router(ServeState::new(
        Arc::clone(&remote),
        first_remote_log,
        Arc::new(Mutex::new(first_remote_registry)),
    )))
    .await;

    let mut local_registry = DeviceRegistry::new();
    local_registry.insert_key(*local.verifying_key());
    local_registry.insert_key(*remote.verifying_key());
    let local_registry = Mutex::new(local_registry);
    let clock = NodeClock::new(&local.device_id());
    let local_log = Mutex::new(OpLog::new());
    let store = Mutex::new(KvStore::new());
    let dir = tempfile::tempdir().unwrap();
    let writer = Mutex::new(OplogWriter::open(&dir.path().join("oplog")).unwrap());
    let mut cursor = RelayCursorV2::START;

    sync_relay_once_v2(
        &first_source,
        &local,
        remote.device_id(),
        &remote.public_key_sec1(),
        &local_registry,
        &clock,
        &local_log,
        &store,
        &mut cursor,
        Some(&writer),
    )
    .await
    .unwrap();
    let first_epoch = cursor.epoch;
    save_relay_cursor(dir.path(), &remote.device_id(), cursor).unwrap();
    let mut cursor = load_relay_cursor(dir.path(), &remote.device_id());

    let restarted_log = Arc::new(Mutex::new(OpLog::new()));
    restarted_log.lock().unwrap().append(old.clone());
    restarted_log.lock().unwrap().append(new.clone());
    let mut restarted_registry = DeviceRegistry::new();
    restarted_registry.insert_key(*remote.verifying_key());
    restarted_registry.insert_key(*local.verifying_key());
    let restarted_source = spawn_app(relay_router(ServeState::new(
        Arc::clone(&remote),
        restarted_log,
        Arc::new(Mutex::new(restarted_registry)),
    )))
    .await;

    let reset = sync_relay_once_v2(
        &restarted_source,
        &local,
        remote.device_id(),
        &remote.public_key_sec1(),
        &local_registry,
        &clock,
        &local_log,
        &store,
        &mut cursor,
        Some(&writer),
    )
    .await
    .unwrap();
    assert!(reset.reset);
    assert_ne!(cursor.epoch, first_epoch);
    assert_eq!(cursor.after, 0);

    let replayed = sync_relay_once_v2(
        &restarted_source,
        &local,
        remote.device_id(),
        &remote.public_key_sec1(),
        &local_registry,
        &clock,
        &local_log,
        &store,
        &mut cursor,
        Some(&writer),
    )
    .await
    .unwrap();
    assert_eq!(replayed.received, 2);
    assert_eq!(replayed.appended, 1);
    assert_eq!(cursor.after, 2);
    assert_eq!(local_log.lock().unwrap().len(), 2);
    assert_eq!(store.lock().unwrap().get("old"), Some(&b"one"[..]));
    assert_eq!(store.lock().unwrap().get("new"), Some(&b"two"[..]));
}

#[tokio::test]
async fn watch_returns_promptly_after_append() {
    let (client, log, head) = spawn_watch_node().await;
    let author = DeviceIdentity::generate();

    let appender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        let op = seal_kv_op(&author, Hlc(1_000), "k", b"v");
        let new_head = op.order_key();
        log.lock().unwrap().append(op);
        head.publish(new_head);
    });

    let start = Instant::now();
    let observed = client
        .watch_head(OrderKey::MIN, Duration::from_secs(10))
        .await
        .unwrap();
    let elapsed = start.elapsed();
    appender.await.unwrap();

    assert_ne!(observed, OrderKey::MIN, "watch returned the unchanged head");
    assert!(
        elapsed < Duration::from_secs(2),
        "watch parked to the deadline instead of waking on the append: {elapsed:?}"
    );
}

#[tokio::test]
async fn watch_times_out_cleanly_at_the_deadline() {
    let (client, _log, _head) = spawn_watch_node().await;
    let start = Instant::now();
    let observed = client
        .watch_head(OrderKey::MIN, Duration::from_millis(300))
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert_eq!(observed, OrderKey::MIN);
    assert!(
        elapsed >= Duration::from_millis(250),
        "watch returned before its hold window: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "watch overran its hold window: {elapsed:?}"
    );
}

#[tokio::test]
async fn watch_head_errs_against_router_without_watch() {
    let app: Router = Router::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = HttpPullSource::new(format!("http://{addr}"));
    let err = client
        .watch_head(OrderKey::MIN, Duration::from_millis(500))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Http(_)), "got {err:?}");
}

#[tokio::test]
async fn watch_parks_when_cursor_is_ahead_of_head() {
    let (base, log, _head) = spawn_watch_node_with_limit(DEFAULT_MAX_PARKED_WATCHES).await;
    let client = HttpPullSource::new(base);
    let author = DeviceIdentity::generate();

    let low = seal_kv_op(&author, Hlc(1_000), "k", b"v");
    let head_key = low.order_key();
    log.lock().unwrap().append(low);

    let ahead = seal_kv_op(&author, Hlc(u64::MAX), "future", b"x").order_key();
    assert!(ahead > head_key, "test cursor must sort ahead of the head");

    let start = Instant::now();
    let observed = client
        .watch_head(ahead, Duration::from_millis(300))
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(250),
        "watch returned early instead of parking on an ahead-cursor: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "watch overran its hold window: {elapsed:?}"
    );
    assert_eq!(observed, head_key);
}

#[tokio::test]
async fn watch_admission_cap_returns_immediately_over_capacity() {
    let (base, _log, _head) = spawn_watch_node_with_limit(1).await;

    let hold_base = base.clone();
    let parked = tokio::spawn(async move {
        HttpPullSource::new(hold_base)
            .watch_head(OrderKey::MIN, Duration::from_secs(3))
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let start = Instant::now();
    let observed = HttpPullSource::new(base)
        .watch_head(OrderKey::MIN, Duration::from_secs(3))
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert_eq!(
        observed,
        OrderKey::MIN,
        "over-cap watch should echo the head"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "over-cap watch parked instead of degrading to an immediate head: {elapsed:?}"
    );

    let _ = parked.await.unwrap();
}

#[tokio::test]
async fn unchanged_head_watch_does_not_busy_loop() {
    let (base, _log, _head) = spawn_watch_node_with_limit(0).await;
    let client = HttpPullSource::new(base);
    let cursor = OrderKey::MIN;

    let window = Duration::from_millis(1_200);
    let deadline = Instant::now() + window;
    let mut calls = 0usize;
    while Instant::now() < deadline {
        let head = client
            .watch_head(cursor, Duration::from_secs(5))
            .await
            .unwrap();
        calls += 1;
        if head <= cursor {
            tokio::time::sleep(WATCH_EMPTY_BACKOFF).await;
        }
    }

    let ceiling = (window.as_millis() / WATCH_EMPTY_BACKOFF.as_millis()) as usize + 3;
    assert!(
        calls <= ceiling,
        "unchanged-head watch re-armed {calls} times in {window:?} (ceiling {ceiling}); \
         it is busy-looping instead of backing off WATCH_EMPTY_BACKOFF"
    );
}

#[tokio::test]
async fn pull_v3_bytes_posts_signed_envelope_and_returns_sealed_page() {
    use crate::pull_v3::{
        PULL_PATH, PULL_V3_VERSION, PullPageV3, PullRequestV3, seal_pull_page_v3,
        sign_pull_request_v3, verify_pull_page_v3, verify_pull_request_v3,
    };
    use axum::routing::post;

    let server = Arc::new(DeviceIdentity::generate());
    let client = DeviceIdentity::generate();
    let client_id = client.device_id();
    let client_sec1 = client.public_key_sec1();
    let server_for_route = Arc::clone(&server);

    let app = Router::new().route(
        PULL_PATH,
        post(move |body: axum::body::Bytes| {
            let server = Arc::clone(&server_for_route);
            async move {
                let (peer, req) = verify_pull_request_v3(&body, 1_000_000, |id| {
                    Ok((*id == client_id).then_some(client_sec1))
                })
                .unwrap();
                assert_eq!(peer, client_id);
                let page = PullPageV3 {
                    version: PULL_V3_VERSION,
                    epoch: req.relay_epoch,
                    reset: false,
                    floor: 0,
                    backfill: Vec::new(),
                    keyed: Vec::new(),
                    next_relay_seq: req.relay_after,
                    head_seq: req.relay_after,
                    resume: None,
                    complete: true,
                    snapshot_recommended: false,
                    store: req.store,
                };
                seal_pull_page_v3(&page, &server, Hlc(100)).unwrap()
            }
        }),
    );
    let source = spawn_app(app).await;
    let request = PullRequestV3 {
        version: PULL_V3_VERSION,
        coverage: Default::default(),
        relay_epoch: "11".repeat(32),
        relay_after: 9,
        resume: None,
        limit: 64,
        audit: false,
        store: Some("trellis".to_string()),
        issued_at_ms: 1_000_000,
    };
    let signed = sign_pull_request_v3(&request, &client, Hlc(50)).unwrap();
    let (status, bytes) = source.pull_v3_bytes(signed).await.unwrap();
    assert_eq!(status, 200);
    let page = verify_pull_page_v3(&bytes, &server.device_id(), &server.public_key_sec1()).unwrap();
    assert!(page.complete);
    assert_eq!(page.next_relay_seq, 9);
    assert_eq!(page.store.as_deref(), Some("trellis"));
}
