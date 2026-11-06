//! Integration tests for Pull Protocol v3 page construction, channel splitting,
//! resume pagination, reset validation, head-window preview, store sweeps, and
//! [`MeshPullSocket`].

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::error::TransportError;
use crate::hlc::{Hlc, NodeClock};
use crate::identity::{DeviceIdentity, encode_hex};
use crate::kv::{KvOp, KvStore, kv_store_id};
use crate::log::OpLog;
use crate::net::{
    CoverageVector, HttpPullSource, MeshPullSocket, OpLogPullSocket, PULL_PAGE_LIMIT_MAX,
    PULL_PATH, PULL_VERSION, PullOutcome, PullPage, PullPhase, PullRequest, RelayCursor, Resume,
    ServeState, build_pull_page, decode_epoch, decode_page_op, drain_pull_pages,
    preview_head_window, preview_resume_after, pull_router, sign_pull_request, sweep_store,
    unix_ms, validate_pull_reset, verify_pull_page,
};
use crate::op::{ENVELOPE_VERSION, OpBody, OpId, OrderKey, SignedOp, StoreId};
use crate::registry::DeviceRegistry;
use crate::store::Store;

fn seal_kv_op(signer: &DeviceIdentity, hlc: u64, key: &str, val: &[u8]) -> SignedOp {
    let payload = KvStore::new()
        .encode(&KvOp::Put {
            key: key.to_string(),
            value: val.to_vec(),
        })
        .unwrap();
    SignedOp::seal(
        OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(hlc),
            device: signer.device_id(),
            store: kv_store_id(),
            payload,
        },
        signer,
    )
    .unwrap()
}

fn seal_custom_store_op(
    signer: &DeviceIdentity,
    hlc: u64,
    store: &str,
    payload: &[u8],
) -> SignedOp {
    SignedOp::seal(
        OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(hlc),
            device: signer.device_id(),
            store: StoreId::new(store).unwrap(),
            payload: payload.to_vec(),
        },
        signer,
    )
    .unwrap()
}

#[tokio::test]
async fn http_pull_source_pull_seals_posts_and_verifies_page() {
    let server = Arc::new(DeviceIdentity::generate());
    let client = DeviceIdentity::generate();
    let other = DeviceIdentity::generate();

    let log = Arc::new(Mutex::new(OpLog::new()));
    let op = seal_custom_store_op(&server, 77, "trellis", b"hello-v3");
    log.lock().unwrap().append(op);

    let mut reg = DeviceRegistry::new();
    reg.insert_key(*server.verifying_key());
    reg.insert_key(*client.verifying_key());
    let devices = Arc::new(Mutex::new(reg));

    let state = ServeState::new(Arc::clone(&server), log, devices);
    let app = pull_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let source = HttpPullSource::new(format!("http://{addr}"));
    let request = PullRequest {
        version: PULL_VERSION,
        coverage: BTreeMap::new(),
        relay_epoch: "00".repeat(32),
        relay_after: 0,
        resume: None,
        limit: 64,
        audit: false,
        store: Some("trellis".to_string()),
        issued_at_ms: unix_ms() as i64,
    };

    let page = source
        .pull(
            &request,
            &client,
            Hlc(80),
            &server.device_id(),
            &server.public_key_sec1(),
        )
        .await
        .unwrap();
    assert!(page.complete);
    assert_eq!(page.head_seq, 1);
    assert_eq!(page.keyed.len(), 1);
    assert_eq!(page.store.as_deref(), Some("trellis"));

    let wrong_peer = source
        .pull(
            &request,
            &client,
            Hlc(81),
            &other.device_id(),
            &other.public_key_sec1(),
        )
        .await
        .unwrap_err();
    assert!(matches!(wrong_peer, TransportError::Verify { .. }));

    let unregistered = source
        .pull(
            &request,
            &other,
            Hlc(82),
            &server.device_id(),
            &server.public_key_sec1(),
        )
        .await
        .unwrap_err();
    assert!(matches!(unregistered, TransportError::Http(_)));
}

#[tokio::test]
async fn drain_splits_channels_fronts_own_origin_and_advances_coverage() {
    let server = Arc::new(DeviceIdentity::generate());
    let client = DeviceIdentity::generate();
    let lower_origin = loop {
        let candidate = DeviceIdentity::generate();
        if candidate.device_id() < server.device_id() {
            break candidate;
        }
    };

    let server_log = Arc::new(Mutex::new(OpLog::new()));
    server_log
        .lock()
        .unwrap()
        .append(seal_kv_op(&server, 100, "own", b"1"));
    server_log
        .lock()
        .unwrap()
        .append(seal_kv_op(&lower_origin, 200, "low", b"2"));

    let mut reg = DeviceRegistry::new();
    reg.insert_key(*server.verifying_key());
    reg.insert_key(*client.verifying_key());
    reg.insert_key(*lower_origin.verifying_key());
    let devices = Arc::new(Mutex::new(reg));

    let state = ServeState::new(
        Arc::clone(&server),
        Arc::clone(&server_log),
        devices.clone(),
    );
    let app = pull_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let source = HttpPullSource::new(format!("http://{addr}"));
    let client_clock = NodeClock::new(&client.device_id());
    let client_log = Mutex::new(OpLog::new());
    let client_store = Mutex::new(KvStore::new());
    let client_coverage = Mutex::new(CoverageVector::new());
    let client_cursors = Mutex::new(BTreeMap::new());

    let socket = OpLogPullSocket {
        identity: &client,
        clock: &client_clock,
        registry: &devices,
        log: &client_log,
        store: &client_store,
        coverage: &client_coverage,
        cursors: &client_cursors,
    };
    let mut relay_cursor: Option<RelayCursor> = None;

    let outcome = drain_pull_pages(
        &socket,
        &source,
        &server.device_id(),
        &server.public_key_sec1(),
        &mut relay_cursor,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(outcome, PullOutcome::Applied(2));
    assert_eq!(client_store.lock().unwrap().get("own"), Some(&b"1"[..]));
    assert_eq!(client_store.lock().unwrap().get("low"), Some(&b"2"[..]));
    assert_eq!(
        socket
            .local_coverage()
            .unwrap()
            .0
            .get(&lower_origin.device_id())
            .map(|k| k.hlc),
        Some(Hlc(200))
    );
    assert_eq!(relay_cursor.map(|c| c.after), Some(2));

    // Late arrival with HLC below existing claim rides Channel B (positional).
    server_log
        .lock()
        .unwrap()
        .append(seal_kv_op(&lower_origin, 50, "late-below-claim", b"3"));
    let second = drain_pull_pages(
        &socket,
        &source,
        &server.device_id(),
        &server.public_key_sec1(),
        &mut relay_cursor,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(second, PullOutcome::Applied(1));
    assert_eq!(
        client_store.lock().unwrap().get("late-below-claim"),
        Some(&b"3"[..])
    );
    assert_eq!(relay_cursor.map(|c| c.after), Some(3));
}

#[tokio::test]
async fn build_pull_page_pages_both_channels_through_resume_tokens() {
    let server = Arc::new(DeviceIdentity::generate());
    let client = DeviceIdentity::generate();
    let first = DeviceIdentity::generate();
    let second = DeviceIdentity::generate();

    let log = Arc::new(Mutex::new(OpLog::new()));
    log.lock()
        .unwrap()
        .append(seal_kv_op(&first, 100, "a1", b"v"));
    log.lock()
        .unwrap()
        .append(seal_kv_op(&second, 200, "b1", b"v"));
    log.lock()
        .unwrap()
        .append(seal_kv_op(&first, 300, "a2", b"v"));

    let mut reg = DeviceRegistry::new();
    for id in [&server, &client, &first, &second] {
        reg.insert_key(*id.verifying_key());
    }
    let state = ServeState::new(Arc::clone(&server), log, Arc::new(Mutex::new(reg)));

    let mut resume: Option<Resume> = None;
    let mut epoch = [0u8; 32];
    let mut after = 0u64;
    let mut delivered = HashSet::new();
    let mut pages = 0;

    loop {
        pages += 1;
        assert!(pages < 16, "pagination must terminate");
        let request = PullRequest {
            version: PULL_VERSION,
            coverage: BTreeMap::new(),
            relay_epoch: encode_hex(&epoch),
            relay_after: after,
            resume: resume.clone(),
            limit: 1,
            audit: false,
            store: None,
            issued_at_ms: unix_ms() as i64,
        };
        let page = build_pull_page(&state, &client.device_id(), &request).unwrap();
        assert!(!page.reset);
        assert!(page.backfill.len() + page.keyed.len() <= 1);
        epoch = decode_epoch(&page.epoch).unwrap();
        after = page.next_relay_seq;
        for (_, encoded) in &page.backfill {
            delivered.insert(
                decode_page_op(encoded, &server.device_id())
                    .unwrap()
                    .id
                    .to_hex(),
            );
        }
        for encoded in &page.keyed {
            delivered.insert(
                decode_page_op(encoded, &server.device_id())
                    .unwrap()
                    .id
                    .to_hex(),
            );
        }
        if page.complete {
            assert!(page.resume.is_none());
            break;
        }
        resume = page.resume;
        assert!(resume.is_some());
    }

    assert_eq!(delivered.len(), 3);
    assert_eq!(after, 3);
}

#[tokio::test]
async fn preview_and_store_sweep_operate_without_advancing_durable_cursors() {
    let server = Arc::new(DeviceIdentity::generate());
    let client = DeviceIdentity::generate();

    let server_log = Arc::new(Mutex::new(OpLog::new()));
    server_log
        .lock()
        .unwrap()
        .append(seal_kv_op(&server, 10, "k1", b"v1"));
    server_log
        .lock()
        .unwrap()
        .append(seal_kv_op(&server, 20, "k2", b"v2"));

    let mut reg = DeviceRegistry::new();
    reg.insert_key(*server.verifying_key());
    reg.insert_key(*client.verifying_key());
    let devices = Arc::new(Mutex::new(reg));

    let state = ServeState::new(Arc::clone(&server), server_log, devices.clone());
    let app = pull_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let source = HttpPullSource::new(format!("http://{addr}"));
    let client_clock = NodeClock::new(&client.device_id());
    let client_log = Mutex::new(OpLog::new());
    let client_store = Mutex::new(KvStore::new());
    let client_coverage = Mutex::new(CoverageVector::new());
    let client_cursors = Mutex::new(BTreeMap::new());

    let socket = OpLogPullSocket {
        identity: &client,
        clock: &client_clock,
        registry: &devices,
        log: &client_log,
        store: &client_store,
        coverage: &client_coverage,
        cursors: &client_cursors,
    };

    let (previewed, next_seq) = preview_head_window(
        &socket,
        &source,
        &server.device_id(),
        &server.public_key_sec1(),
        None,
        1,
    )
    .await
    .unwrap();
    assert_eq!(previewed, 1);
    assert_eq!(next_seq, 2);
    assert_eq!(client_store.lock().unwrap().get("k2"), Some(&b"v2"[..]));
    assert!(client_store.lock().unwrap().get("k1").is_none());
    assert!(client_cursors.lock().unwrap().is_empty());
    assert!(client_coverage.lock().unwrap().0.is_empty());

    let swept = sweep_store(
        &socket,
        &source,
        &server.device_id(),
        &server.public_key_sec1(),
        None,
        kv_store_id().as_str(),
    )
    .await
    .unwrap();
    assert_eq!(swept, 2);
    assert_eq!(client_store.lock().unwrap().get("k1"), Some(&b"v1"[..]));
    assert!(client_cursors.lock().unwrap().is_empty());
}

#[test]
fn validate_pull_reset_and_preview_resume_after_enforce_protocol_invariants() {
    let head = u64::from(PULL_PAGE_LIMIT_MAX) * 3;
    assert_eq!(
        preview_resume_after(None, head),
        head - u64::from(PULL_PAGE_LIMIT_MAX)
    );
    assert_eq!(preview_resume_after(Some(head - 5), head), head - 5);
    assert_eq!(
        preview_resume_after(Some(1), head),
        head - u64::from(PULL_PAGE_LIMIT_MAX)
    );

    let request = PullRequest {
        version: PULL_VERSION,
        coverage: BTreeMap::new(),
        relay_epoch: encode_hex(&[1u8; 32]),
        relay_after: 5,
        resume: None,
        limit: PULL_PAGE_LIMIT_MAX,
        audit: false,
        store: None,
        issued_at_ms: 1_000,
    };
    let bad_floor = PullPage {
        version: PULL_VERSION,
        epoch: encode_hex(&[2u8; 32]),
        reset: true,
        floor: 10,
        backfill: Vec::new(),
        keyed: Vec::new(),
        next_relay_seq: 0,
        head_seq: 5,
        resume: None,
        complete: false,
        snapshot_recommended: false,
        store: None,
    };
    assert!(
        validate_pull_reset(&request, &bad_floor, [2u8; 32])
            .unwrap_err()
            .contains("invalid pull reset")
    );

    let valid_reset = PullPage {
        floor: 2,
        head_seq: 5,
        ..bad_floor
    };
    assert_eq!(
        validate_pull_reset(&request, &valid_reset, [2u8; 32]).unwrap(),
        RelayCursor::new([2u8; 32], 2)
    );

    let _ = (
        PULL_PATH,
        PullPhase::Keyed,
        OpId::from_bytes([0; 32]),
        OrderKey::MIN,
    );
    let _ = (sign_pull_request, verify_pull_page);
}
