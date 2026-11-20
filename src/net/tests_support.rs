use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::get;

use super::relay::{
    DEVICE_BOOK_NONCE_HEADER, DEVICE_BOOK_SIGNATURE_HEADER, RELAY_CALLER_HEADER,
    RELAY_NONCE_HEADER, RELAY_OPS_REQUEST_CONTEXT, RELAY_OPS_SIGNING_CONTEXT,
    RELAY_REQUEST_SIGNATURE_HEADER, RELAY_SIGNATURE_HEADER, sign_device_book, sign_relay_request,
    sign_relay_response,
};
use super::server::octet;
use super::{
    DEFAULT_MAX_PARKED_WATCHES, DeviceEntry, DevicesResp, HeadPublisher, HttpPullSource,
    RELAY_PROTOCOL_VERSION, RelayCursor, RelayResponse, RelayWireEntry, ServeState,
    decode_fixed_hex, router,
};
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity, encode_hex};
use crate::kv::{KvOp, KvStore, kv_store_id};
use crate::log::{LogSource, OpLog, RelayStreamState};
use crate::op::{ENVELOPE_VERSION, OpBody, OpId, OrderKey, SignedOp};
use crate::registry::{DeviceBook, DeviceRegistry};
use crate::store::Store;

pub(super) async fn spawn_app(app: Router) -> HttpPullSource {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    HttpPullSource::new(format!("http://{addr}"))
}

pub(super) async fn spawn_devices_response(
    body: Vec<u8>,
    signed_body: Option<Vec<u8>>,
    signer: Option<Arc<DeviceIdentity>>,
) -> HttpPullSource {
    let app = Router::new().route(
        "/devices",
        get(move |headers: HeaderMap| {
            let body = body.clone();
            let signed_body = signed_body.clone();
            let signer = signer.clone();
            async move {
                let mut response = octet(body);
                if let (Some(signed_body), Some(signer)) = (signed_body, signer) {
                    let nonce = headers
                        .get(DEVICE_BOOK_NONCE_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(decode_fixed_hex::<32>)
                        .expect("attested client must send a valid nonce");
                    let signature = encode_hex(&sign_device_book(&signer, &nonce, &signed_body));
                    response.headers_mut().insert(
                        HeaderName::from_static(DEVICE_BOOK_SIGNATURE_HEADER),
                        HeaderValue::from_str(&signature).unwrap(),
                    );
                }
                response
            }
        }),
    );
    spawn_app(app).await
}

pub(super) fn encoded_devices(devices: &[&DeviceIdentity]) -> Vec<u8> {
    postcard::to_allocvec(&DevicesResp {
        devices: devices
            .iter()
            .map(|identity| DeviceEntry {
                device_id: *identity.device_id().as_bytes(),
                public_key_sec1: identity.public_key_sec1().to_vec(),
            })
            .collect(),
    })
    .unwrap()
}

pub(super) fn encoded_relay_response(
    epoch: [u8; 32],
    head: u64,
    next: u64,
    entries: Vec<RelayWireEntry>,
) -> Vec<u8> {
    postcard::to_allocvec(&RelayResponse {
        v: RELAY_PROTOCOL_VERSION,
        epoch,
        head,
        floor: 0,
        next,
        reset: false,
        entries,
    })
    .unwrap()
}

pub(super) async fn spawn_relay_ops_response(
    body: Vec<u8>,
    signed_body: Vec<u8>,
    signer: Arc<DeviceIdentity>,
    cursor: RelayCursor,
    limit: u16,
    signing_nonce: Option<[u8; 32]>,
) -> HttpPullSource {
    let app = Router::new().route(
        "/relay/ops",
        get(move |headers: HeaderMap| {
            let body = body.clone();
            let signed_body = signed_body.clone();
            let signer = signer.clone();
            async move {
                let request_nonce = headers
                    .get(RELAY_NONCE_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(decode_fixed_hex::<32>)
                    .expect("v2 client must send a valid nonce");
                let caller = headers
                    .get(RELAY_CALLER_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(decode_fixed_hex::<32>)
                    .map(DeviceId::from_bytes)
                    .expect("v2 client must send a valid caller id");
                let nonce = signing_nonce.unwrap_or(request_nonce);
                let signature = sign_relay_response(
                    &signer,
                    &caller,
                    RELAY_OPS_SIGNING_CONTEXT,
                    &cursor.epoch,
                    cursor.after,
                    limit as u64,
                    &nonce,
                    &signed_body,
                );
                let mut response = octet(body);
                response.headers_mut().insert(
                    HeaderName::from_static(RELAY_SIGNATURE_HEADER),
                    HeaderValue::from_str(&encode_hex(&signature)).unwrap(),
                );
                response
            }
        }),
    );
    spawn_app(app).await.with_limit(limit)
}

pub(super) async fn raw_relay_ops_request(
    client: &HttpPullSource,
    caller: &DeviceIdentity,
    serving_peer: DeviceId,
    cursor: RelayCursor,
    signed_limit: u16,
    url_limit: u16,
    nonce: [u8; 32],
) -> reqwest::Response {
    let signature = sign_relay_request(
        caller,
        RELAY_OPS_REQUEST_CONTEXT,
        &serving_peer,
        &cursor.epoch,
        cursor.after,
        signed_limit as u64,
        &nonce,
    );
    client
        .client
        .get(format!(
            "{}/relay/ops?epoch={}&after={}&limit={url_limit}",
            client.base_url,
            encode_hex(&cursor.epoch),
            cursor.after,
        ))
        .header(RELAY_NONCE_HEADER, encode_hex(&nonce))
        .header(RELAY_CALLER_HEADER, caller.device_id().to_hex())
        .header(RELAY_REQUEST_SIGNATURE_HEADER, encode_hex(&signature))
        .send()
        .await
        .unwrap()
}

#[derive(Clone)]
pub(super) struct FailingDeviceBook;

impl DeviceBook for FailingDeviceBook {
    fn known_devices(&self) -> Vec<(DeviceId, [u8; 33])> {
        panic!("serving must use the fallible device-book read")
    }

    fn try_known_devices(&self) -> Result<Vec<(DeviceId, [u8; 33])>, String> {
        Err("database read failed".into())
    }
}

#[derive(Clone)]
pub(super) struct StateOnlyRelayLog {
    pub(super) log: Arc<Mutex<OpLog>>,
    pub(super) page_calls: Arc<AtomicUsize>,
}

impl LogSource for StateOnlyRelayLog {
    fn since(&self, cursor: OrderKey, limit: usize) -> Vec<SignedOp> {
        self.log
            .lock()
            .unwrap()
            .since(cursor)
            .take(limit)
            .cloned()
            .collect()
    }

    fn head(&self) -> Option<OrderKey> {
        self.log.lock().unwrap().head()
    }

    fn contains(&self, id: &OpId) -> bool {
        self.log.lock().unwrap().contains(id)
    }

    fn relay_state(&self) -> Result<Option<RelayStreamState>, String> {
        Ok(Some(self.log.lock().unwrap().relay_state()))
    }

    fn relay_page(
        &self,
        _after: u64,
        _limit: usize,
    ) -> Result<Option<crate::log::RelayLogPage>, String> {
        self.page_calls.fetch_add(1, AtomicOrdering::Relaxed);
        Err("relay page must not be queried".into())
    }
}

#[derive(Clone)]
pub(super) struct V1OnlyLog(pub(super) Arc<Mutex<OpLog>>);

impl LogSource for V1OnlyLog {
    fn since(&self, cursor: OrderKey, limit: usize) -> Vec<SignedOp> {
        self.0
            .lock()
            .unwrap()
            .since(cursor)
            .take(limit)
            .cloned()
            .collect()
    }

    fn head(&self) -> Option<OrderKey> {
        self.0.lock().unwrap().head()
    }

    fn contains(&self, id: &OpId) -> bool {
        self.0.lock().unwrap().contains(id)
    }
}

pub(super) fn seal_kv_op(id: &DeviceIdentity, hlc: Hlc, key: &str, value: &[u8]) -> SignedOp {
    let payload = KvStore::new()
        .encode(&KvOp::Put {
            key: key.to_string(),
            value: value.to_vec(),
        })
        .unwrap();
    let body = OpBody {
        v: ENVELOPE_VERSION,
        hlc,
        device: id.device_id(),
        store: kv_store_id(),
        payload,
    };
    SignedOp::seal(body, id).unwrap()
}

pub(super) async fn spawn_watch_node_with_limit(
    watch_limit: usize,
) -> (String, Arc<Mutex<OpLog>>, HeadPublisher) {
    let identity = Arc::new(DeviceIdentity::generate());
    let log = Arc::new(Mutex::new(OpLog::new()));
    let mut reg = DeviceRegistry::new();
    reg.insert_key(*identity.verifying_key());
    let devices = Arc::new(Mutex::new(reg));

    let head = HeadPublisher::new(OrderKey::MIN);
    let state = ServeState::new(identity, log.clone(), devices)
        .with_watch(head.watch())
        .with_watch_limit(watch_limit);
    let app = router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), log, head)
}

pub(super) async fn spawn_watch_node() -> (HttpPullSource, Arc<Mutex<OpLog>>, HeadPublisher) {
    let (base, log, head) = spawn_watch_node_with_limit(DEFAULT_MAX_PARKED_WATCHES).await;
    (HttpPullSource::new(base), log, head)
}

mod pull_budget {
    use super::*;
    use crate::net::{
        PULL_PAGE_LIMIT_MAX, PULL_VERSION, PullRequest, Resume, build_pull_page, decode_epoch,
        decode_page_op, unix_ms,
    };
    use std::collections::HashSet;

    #[test]
    fn encode_origin_rows_defers_overflow_row_and_admits_lone_oversize() {
        use crate::net::{MAX_PULL_RESPONSE_BYTES, PULL_PAGE_BYTE_BUDGET, encode_origin_rows};

        let author = DeviceIdentity::generate();
        let k1 = seal_kv_op(&author, Hlc(1), "k1", b"v").order_key();
        let k2 = seal_kv_op(&author, Hlc(2), "k2", b"v").order_key();
        let k3 = seal_kv_op(&author, Hlc(3), "k3", b"v").order_key();

        // base64 lengths: 30 raw -> 40, 60 raw -> 80.
        let small = vec![0u8; 30];
        let big = vec![0u8; 60];

        // Two small rows fit the 90-byte budget; the big row would overflow it and
        // must be deferred, not appended past the budget.
        let mut keyed = Vec::new();
        let mut bytes = 0usize;
        let (served, last_key) = encode_origin_rows(
            vec![(k1, small.clone()), (k2, small.clone()), (k3, big.clone())],
            &mut keyed,
            &mut bytes,
            90,
        );
        assert_eq!(served, 2);
        assert_eq!(last_key, Some(k2));
        assert_eq!(bytes, 80);
        assert_eq!(keyed.len(), 2);

        // A lone row larger than the budget is still admitted so the drain keeps
        // advancing (progress guarantee for a single oversized op).
        let mut keyed = Vec::new();
        let mut bytes = 0usize;
        let (served, last_key) = encode_origin_rows(vec![(k3, big)], &mut keyed, &mut bytes, 10);
        assert_eq!(served, 1);
        assert_eq!(last_key, Some(k3));
        assert_eq!(bytes, 80);

        // Sanity: the real constants still admit one protocol-max row.
        const { assert!(PULL_PAGE_BYTE_BUDGET < MAX_PULL_RESPONSE_BYTES) };
    }

    #[tokio::test]
    async fn build_pull_page_backfill_cuts_before_oversized_row() {
        use crate::net::{MAX_PULL_RESPONSE_BYTES, PULL_PAGE_BYTE_BUDGET};

        let server = Arc::new(DeviceIdentity::generate());
        let client = DeviceIdentity::generate();
        let author = DeviceIdentity::generate();

        // One oversized op (mirrors the 39.4 MiB party_files video envelope that
        // wedged yin) between two small ops, all fully covered by the puller so
        // they arrive on the positional backfill channel.
        let big_val = vec![7u8; 25 * 1024 * 1024];
        let op1 = seal_kv_op(&author, Hlc(100), "small-1", b"v");
        let op2 = seal_kv_op(&author, Hlc(200), "big", &big_val);
        let op3 = seal_kv_op(&author, Hlc(300), "small-2", b"v");

        let log = Arc::new(Mutex::new(OpLog::new()));
        for op in [&op1, &op2, &op3] {
            log.lock().unwrap().append(op.clone());
        }

        let mut reg = DeviceRegistry::new();
        for id in [&server, &client, &author] {
            reg.insert_key(*id.verifying_key());
        }
        let state = ServeState::new(Arc::clone(&server), log, Arc::new(Mutex::new(reg)));

        // Claim the newest op so every op is served positionally on Channel B.
        let coverage = crate::net::CoverageVector(std::collections::BTreeMap::from([(
            author.device_id(),
            op3.order_key(),
        )]))
        .to_wire_map();

        let mut resume: Option<Resume> = None;
        let mut epoch = [0u8; 32];
        let mut after = 0u64;
        let mut delivered = HashSet::new();
        let mut saw_lone_oversize_page = false;
        let mut pages = 0;

        loop {
            pages += 1;
            assert!(pages < 8, "pagination must terminate");
            let request = PullRequest {
                version: PULL_VERSION,
                coverage: coverage.clone(),
                relay_epoch: encode_hex(&epoch),
                relay_after: after,
                resume: resume.clone(),
                limit: PULL_PAGE_LIMIT_MAX,
                audit: false,
                store: None,
                issued_at_ms: unix_ms() as i64,
            };
            let page = build_pull_page(&state, &client.device_id(), &request).unwrap();
            assert!(!page.reset);
            assert!(page.keyed.is_empty(), "fully claimed ops skip Channel A");

            let page_bytes: usize = page
                .backfill
                .iter()
                .map(|(_, encoded)| encoded.len())
                .sum::<usize>()
                + page.keyed.iter().map(String::len).sum::<usize>();
            if page.backfill.len() > 1 {
                // Multi-row pages must respect the byte budget (pre-push guard).
                assert!(
                    page_bytes <= PULL_PAGE_BYTE_BUDGET,
                    "multi-row page exceeded PULL_PAGE_BYTE_BUDGET: {page_bytes}"
                );
            } else if page.backfill.len() == 1 {
                let row_bytes = page.backfill[0].1.len();
                if row_bytes > PULL_PAGE_BYTE_BUDGET {
                    // A lone oversized row is admitted for progress but must stay
                    // under the client-side MAX_PULL_RESPONSE_BYTES rejection cap.
                    saw_lone_oversize_page = true;
                    assert!(row_bytes < MAX_PULL_RESPONSE_BYTES);
                }
            }

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
            if page.complete {
                assert!(page.resume.is_none());
                break;
            }
            resume = page.resume;
            assert!(resume.is_some());
        }

        assert!(
            saw_lone_oversize_page,
            "oversized op must be isolated on its own page"
        );
        assert_eq!(delivered.len(), 3);
        assert_eq!(after, 3);
    }
}
