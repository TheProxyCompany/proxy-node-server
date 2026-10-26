use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;

use super::relay::{
    DEVICE_BOOK_NONCE_HEADER, DEVICE_BOOK_SIGNATURE_HEADER, RELAY_REPLAY_LIMIT,
    RELAY_SIGNATURE_HEADER, sign_device_book, verify_device_book,
};
use super::tests_support::{
    FailingDeviceBook, StateOnlyRelayLog, encoded_devices, encoded_relay_response,
    raw_relay_ops_request, seal_kv_op, spawn_app, spawn_devices_response, spawn_relay_ops_response,
};
use super::{
    DEFAULT_PULL_LIMIT, HeadPublisher, RelayCursorV2, RelayWireEntryV2, ServeState, router,
};
use crate::error::TransportError;
use crate::hlc::Hlc;
use crate::identity::{DeviceIdentity, encode_hex};
use crate::log::OpLog;
use crate::registry::DeviceRegistry;

#[tokio::test]
async fn attested_devices_verify_serving_peer_and_keep_legacy_body() {
    let serving = Arc::new(DeviceIdentity::generate());
    let historical = DeviceIdentity::generate();
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*historical.verifying_key());
    let app = router(ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        Arc::new(Mutex::new(registry)),
    ));
    let client = spawn_app(app).await;

    let legacy = client.fetch_devices().await.unwrap();
    assert_eq!(legacy.devices.len(), 2, "legacy postcard body is unchanged");

    let attested = client
        .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
        .await
        .unwrap();
    assert_eq!(attested.devices.len(), 2);
    assert!(
        attested
            .devices
            .iter()
            .any(|entry| entry.device_id == *historical.device_id().as_bytes())
    );
}

#[tokio::test]
async fn attested_devices_reject_tampered_body() {
    let serving = Arc::new(DeviceIdentity::generate());
    let original = encoded_devices(&[&serving]);
    let injected = DeviceIdentity::generate();
    let tampered = encoded_devices(&[&serving, &injected]);
    let client = spawn_devices_response(tampered, Some(original), Some(Arc::clone(&serving))).await;

    let error = client
        .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}

#[tokio::test]
async fn attested_devices_reject_wrong_signature() {
    let serving = DeviceIdentity::generate();
    let attacker = Arc::new(DeviceIdentity::generate());
    let body = encoded_devices(&[&serving]);
    let client =
        spawn_devices_response(body.clone(), Some(body), Some(Arc::clone(&attacker))).await;

    let error = client
        .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}

#[tokio::test]
async fn attested_devices_reject_wrong_pinned_key() {
    let serving = Arc::new(DeviceIdentity::generate());
    let wrong_peer = DeviceIdentity::generate();
    let body = encoded_devices(&[&serving]);
    let client = spawn_devices_response(body.clone(), Some(body), Some(Arc::clone(&serving))).await;

    let error = client
        .fetch_attested_devices(wrong_peer.device_id(), &wrong_peer.public_key_sec1())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}

#[tokio::test]
async fn attested_devices_reject_missing_signature_header() {
    let serving = DeviceIdentity::generate();
    let client = spawn_devices_response(encoded_devices(&[&serving]), None, None).await;

    let error = client
        .fetch_attested_devices(serving.device_id(), &serving.public_key_sec1())
        .await
        .unwrap_err();
    assert!(
        matches!(error, TransportError::Wire(message) if message.contains("missing x-proxy-device-book-signature"))
    );
}

#[test]
fn attested_devices_reject_replayed_signature_for_a_different_nonce() {
    let serving = DeviceIdentity::generate();
    let body = encoded_devices(&[&serving]);
    let original_nonce = [0x11; 32];
    let next_nonce = [0x22; 32];
    let replayed_signature = encode_hex(&sign_device_book(&serving, &original_nonce, &body));

    let error = verify_device_book(
        serving.device_id(),
        &serving.public_key_sec1(),
        &next_nonce,
        &body,
        &replayed_signature,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}

#[tokio::test]
async fn devices_source_failure_is_not_signed_as_an_empty_book() {
    let serving = Arc::new(DeviceIdentity::generate());
    let app = router(ServeState::new(
        serving,
        Arc::new(Mutex::new(OpLog::new())),
        FailingDeviceBook,
    ));
    let client = spawn_app(app).await;

    let response = client
        .client
        .get(format!("{}/devices", client.base_url))
        .header(DEVICE_BOOK_NONCE_HEADER, encode_hex(&[0x33; 32]))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(DEVICE_BOOK_SIGNATURE_HEADER)
            .is_none()
    );
}

#[tokio::test]
async fn relay_v2_invalid_cursor_resets_before_querying_page() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let page_calls = Arc::new(AtomicUsize::new(0));
    let source = StateOnlyRelayLog {
        log: Arc::new(Mutex::new(OpLog::new())),
        page_calls: Arc::clone(&page_calls),
    };
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*caller.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        source,
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    let state = client
        .fetch_relay_head_v2(
            &caller,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2::START,
        )
        .await
        .unwrap();
    let reset = client
        .fetch_relay_ops_v2(
            &caller,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2 {
                epoch: state.epoch,
                after: u64::MAX,
            },
        )
        .await
        .unwrap();

    assert!(reset.reset);
    assert_eq!(reset.next, reset.floor);
    assert_eq!(page_calls.load(AtomicOrdering::Relaxed), 0);
}

#[tokio::test]
async fn relay_v2_rejects_oversized_page_before_querying_source() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let page_calls = Arc::new(AtomicUsize::new(0));
    let source = StateOnlyRelayLog {
        log: Arc::new(Mutex::new(OpLog::new())),
        page_calls: Arc::clone(&page_calls),
    };
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*caller.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        source,
        Arc::new(Mutex::new(registry)),
    )))
    .await
    .with_limit(DEFAULT_PULL_LIMIT + 1);

    let error = client
        .fetch_relay_ops_v2(
            &caller,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2::START,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Http(message) if message == "status 400 Bad Request"));
    assert_eq!(page_calls.load(AtomicOrdering::Relaxed), 0);
}

#[tokio::test]
async fn relay_v2_rejects_unknown_caller_without_signed_response() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    let response = raw_relay_ops_request(
        &client,
        &caller,
        serving.device_id(),
        RelayCursorV2::START,
        1,
        1,
        [0x31; 32],
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
}

#[tokio::test]
async fn relay_v2_fails_closed_when_caller_lookup_fails() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        FailingDeviceBook,
    )))
    .await;

    let response = raw_relay_ops_request(
        &client,
        &caller,
        serving.device_id(),
        RelayCursorV2::START,
        1,
        1,
        [0x32; 32],
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
}

#[tokio::test]
async fn relay_v2_rejects_request_query_tampering() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*caller.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    let response = raw_relay_ops_request(
        &client,
        &caller,
        serving.device_id(),
        RelayCursorV2::START,
        1,
        2,
        [0x33; 32],
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
}

#[tokio::test]
async fn relay_v2_rejects_a_replayed_authenticated_request() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*caller.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        Arc::new(Mutex::new(registry)),
    )))
    .await;
    let nonce = [0x34; 32];

    let first = raw_relay_ops_request(
        &client,
        &caller,
        serving.device_id(),
        RelayCursorV2::START,
        1,
        1,
        nonce,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let replay = raw_relay_ops_request(
        &client,
        &caller,
        serving.device_id(),
        RelayCursorV2::START,
        1,
        1,
        nonce,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert!(replay.headers().get(RELAY_SIGNATURE_HEADER).is_none());
}

#[tokio::test]
async fn relay_v2_never_evicts_an_unexpired_replay_nonce_at_capacity() {
    let serving = Arc::new(DeviceIdentity::generate());
    let caller = DeviceIdentity::generate();
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*caller.verifying_key());
    let state = ServeState::new(
        Arc::clone(&serving),
        Arc::new(Mutex::new(OpLog::new())),
        Arc::new(Mutex::new(registry)),
    );
    {
        let mut replays = state.relay_replays.lock().unwrap();
        for index in 0..RELAY_REPLAY_LIMIT {
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            replays.insert((caller.device_id(), nonce), Instant::now());
        }
    }
    let client = spawn_app(router(state)).await;

    let response = raw_relay_ops_request(
        &client,
        &caller,
        serving.device_id(),
        RelayCursorV2::START,
        1,
        1,
        [0xff; 32],
    )
    .await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().get(RELAY_SIGNATURE_HEADER).is_none());
}

#[tokio::test]
async fn relay_v2_delivers_a_late_lower_order_key_by_arrival_sequence() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let high = seal_kv_op(&author, Hlc(30), "high", b"first");
    let low = seal_kv_op(&author, Hlc(10), "low", b"late");
    assert!(low.order_key() < high.order_key());

    let log = Arc::new(Mutex::new(OpLog::new()));
    log.lock().unwrap().append(high.clone());
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*author.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        Arc::clone(&log),
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    let first = client
        .fetch_relay_ops_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2::START,
        )
        .await
        .unwrap();
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].seq, 1);
    assert_eq!(first.entries[0].op.id, high.id);
    let status = client
        .fetch_relay_head_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            first.cursor(),
        )
        .await
        .unwrap();
    assert_eq!(status.head, 1);
    assert_eq!(status.next, 1);
    assert!(status.entries.is_empty());

    log.lock().unwrap().append(low.clone());
    let late = client
        .fetch_relay_ops_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            first.cursor(),
        )
        .await
        .unwrap();
    assert_eq!(late.entries.len(), 1);
    assert_eq!(late.entries[0].seq, 2);
    assert_eq!(late.entries[0].op.id, low.id);
}

#[tokio::test]
async fn relay_v2_epoch_mismatch_returns_authenticated_reset() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let log = Arc::new(Mutex::new(OpLog::new()));
    log.lock()
        .unwrap()
        .append(seal_kv_op(&author, Hlc(10), "k", b"v"));
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*author.verifying_key());
    let client = spawn_app(router(ServeState::new(
        Arc::clone(&serving),
        log,
        Arc::new(Mutex::new(registry)),
    )))
    .await;

    let reset = client
        .fetch_relay_ops_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2 {
                epoch: [0x99; 32],
                after: 1,
            },
        )
        .await
        .unwrap();
    assert!(reset.reset);
    assert!(reset.entries.is_empty());
    assert_eq!(reset.next, reset.floor);
    assert_ne!(reset.epoch, [0x99; 32]);
}

#[tokio::test]
async fn relay_v2_watch_wakes_for_a_unique_late_lower_order_key() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let high = seal_kv_op(&author, Hlc(30), "high", b"first");
    let low = seal_kv_op(&author, Hlc(10), "low", b"late");
    let semantic_head = high.order_key();
    assert!(low.order_key() < semantic_head);

    let log = Arc::new(Mutex::new(OpLog::new()));
    log.lock().unwrap().append(high);
    let mut registry = DeviceRegistry::new();
    registry.insert_key(*serving.verifying_key());
    registry.insert_key(*author.verifying_key());
    let publisher = HeadPublisher::new(semantic_head);
    let client = spawn_app(router(
        ServeState::new(
            Arc::clone(&serving),
            Arc::clone(&log),
            Arc::new(Mutex::new(registry)),
        )
        .with_watch(publisher.watch()),
    ))
    .await;
    let first = client
        .fetch_relay_ops_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            RelayCursorV2::START,
        )
        .await
        .unwrap();
    assert_eq!(first.head, 1);

    let append_log = Arc::clone(&log);
    let appender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(append_log.lock().unwrap().append(low));
        publisher.publish(semantic_head);
    });
    let start = Instant::now();
    let observed = client
        .watch_relay_head_v2(
            &author,
            serving.device_id(),
            &serving.public_key_sec1(),
            first.cursor(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    appender.await.unwrap();

    assert_eq!(observed.head, 2);
    assert_eq!(observed.next, 1, "watch must not advance the pull cursor");
    assert!(observed.entries.is_empty());
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn relay_v2_rejects_tampered_sequence_body() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let envelope = seal_kv_op(&author, Hlc(10), "k", b"v").to_bytes().unwrap();
    let epoch = [0x44; 32];
    let cursor = RelayCursorV2 { epoch, after: 0 };
    let signed = encoded_relay_response(
        epoch,
        1,
        1,
        vec![RelayWireEntryV2 {
            seq: 1,
            envelope: envelope.clone(),
        }],
    );
    let tampered = encoded_relay_response(epoch, 2, 2, vec![RelayWireEntryV2 { seq: 2, envelope }]);
    let client =
        spawn_relay_ops_response(tampered, signed, Arc::clone(&serving), cursor, 10, None).await;

    let error = client
        .fetch_relay_ops_v2(
            &serving,
            serving.device_id(),
            &serving.public_key_sec1(),
            cursor,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}

#[tokio::test]
async fn relay_v2_rejects_tampered_envelope_body() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let envelope = seal_kv_op(&author, Hlc(10), "k", b"v").to_bytes().unwrap();
    let mut tampered_envelope = envelope.clone();
    let last = tampered_envelope.last_mut().unwrap();
    *last ^= 0x01;
    let epoch = [0x45; 32];
    let cursor = RelayCursorV2 { epoch, after: 0 };
    let signed = encoded_relay_response(epoch, 1, 1, vec![RelayWireEntryV2 { seq: 1, envelope }]);
    let tampered = encoded_relay_response(
        epoch,
        1,
        1,
        vec![RelayWireEntryV2 {
            seq: 1,
            envelope: tampered_envelope,
        }],
    );
    let client =
        spawn_relay_ops_response(tampered, signed, Arc::clone(&serving), cursor, 10, None).await;

    let error = client
        .fetch_relay_ops_v2(
            &serving,
            serving.device_id(),
            &serving.public_key_sec1(),
            cursor,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}

#[tokio::test]
async fn relay_v2_rejects_signed_non_monotonic_sequences_before_envelopes() {
    let serving = Arc::new(DeviceIdentity::generate());
    let author = DeviceIdentity::generate();
    let envelope = seal_kv_op(&author, Hlc(10), "k", b"v").to_bytes().unwrap();
    let epoch = [0x55; 32];
    let cursor = RelayCursorV2 { epoch, after: 0 };
    let body = encoded_relay_response(
        epoch,
        2,
        1,
        vec![
            RelayWireEntryV2 {
                seq: 2,
                envelope: envelope.clone(),
            },
            RelayWireEntryV2 { seq: 1, envelope },
        ],
    );
    let client =
        spawn_relay_ops_response(body.clone(), body, Arc::clone(&serving), cursor, 10, None).await;

    let error = client
        .fetch_relay_ops_v2(
            &serving,
            serving.device_id(),
            &serving.public_key_sec1(),
            cursor,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, TransportError::Wire(message) if message.contains("strictly increasing"))
    );
}

#[tokio::test]
async fn relay_v2_rejects_signed_malformed_envelope() {
    let serving = Arc::new(DeviceIdentity::generate());
    let epoch = [0x66; 32];
    let cursor = RelayCursorV2 { epoch, after: 0 };
    let body = encoded_relay_response(
        epoch,
        1,
        1,
        vec![RelayWireEntryV2 {
            seq: 1,
            envelope: vec![0xff],
        }],
    );
    let client =
        spawn_relay_ops_response(body.clone(), body, Arc::clone(&serving), cursor, 10, None).await;

    let error = client
        .fetch_relay_ops_v2(
            &serving,
            serving.device_id(),
            &serving.public_key_sec1(),
            cursor,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Op(_)));
}

#[tokio::test]
async fn relay_v2_checks_page_limit_before_decoding_envelopes() {
    let serving = Arc::new(DeviceIdentity::generate());
    let epoch = [0x67; 32];
    let cursor = RelayCursorV2 { epoch, after: 0 };
    let body = encoded_relay_response(
        epoch,
        2,
        2,
        vec![
            RelayWireEntryV2 {
                seq: 1,
                envelope: vec![0xff],
            },
            RelayWireEntryV2 {
                seq: 2,
                envelope: vec![0xff],
            },
        ],
    );
    let client =
        spawn_relay_ops_response(body.clone(), body, Arc::clone(&serving), cursor, 1, None).await;

    let error = client
        .fetch_relay_ops_v2(
            &serving,
            serving.device_id(),
            &serving.public_key_sec1(),
            cursor,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Wire(message) if message.contains("requested limit")));
}

#[tokio::test]
async fn relay_v2_rejects_signature_from_an_unpinned_key() {
    let serving = DeviceIdentity::generate();
    let attacker = Arc::new(DeviceIdentity::generate());
    let epoch = [0x77; 32];
    let cursor = RelayCursorV2 { epoch, after: 0 };
    let body = encoded_relay_response(epoch, 0, 0, Vec::new());
    let client = spawn_relay_ops_response(body.clone(), body, attacker, cursor, 10, None).await;

    let error = client
        .fetch_relay_ops_v2(
            &serving,
            serving.device_id(),
            &serving.public_key_sec1(),
            cursor,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Identity(crate::error::IdentityError::BadSignature)
    ));
}
