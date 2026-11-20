use super::*;

#[test]
fn encode_origin_rows_defers_overflow_row_and_admits_lone_oversize() {
    use crate::net::{MAX_PULL_RESPONSE_BYTES, PULL_PAGE_BYTE_BUDGET, encode_origin_rows};

    let author = DeviceIdentity::generate();
    let k1 = seal_kv_op(&author, 1, "k1", b"v").order_key();
    let k2 = seal_kv_op(&author, 2, "k2", b"v").order_key();
    let k3 = seal_kv_op(&author, 3, "k3", b"v").order_key();

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
    let op1 = seal_kv_op(&author, 100, "small-1", b"v");
    let op2 = seal_kv_op(&author, 200, "big", &big_val);
    let op3 = seal_kv_op(&author, 300, "small-2", b"v");

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
