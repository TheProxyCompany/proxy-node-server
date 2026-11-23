
use super::*;
use crate::row_op::{Column, KeyField, Mutation, ORIGIN_LOCAL, ProxyDbOp, Scalar};
use crate::sqlite::{coverage, oplog};
use crate::{DeviceIdentity, ENVELOPE_VERSION, OpBody, SignedOp, StoreId};
use rusqlite::Connection;

fn text_col(name: &str, value: impl Into<String>) -> Column {
    Column {
        name: name.to_string(),
        value: Scalar::Text(value.into()),
    }
}

fn text_key(col: &str, value: impl Into<String>) -> KeyField {
    KeyField {
        col: col.to_string(),
        val: Scalar::Text(value.into()),
    }
}

fn setup_oplog_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE devices (
                device_id TEXT PRIMARY KEY,
                public_key BLOB,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                is_local INTEGER NOT NULL DEFAULT 0,
                trusted INTEGER NOT NULL DEFAULT 0,
                introduced_by TEXT
            );
            ATTACH DATABASE ':memory:' AS oplog_db;
            PRAGMA oplog_db.auto_vacuum = INCREMENTAL;
            CREATE TABLE oplog_db.oplog (
                op_id BLOB PRIMARY KEY,
                hlc INTEGER NOT NULL,
                device_id BLOB NOT NULL,
                store_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_pk TEXT NOT NULL,
                payload BLOB NOT NULL,
                envelope BLOB NOT NULL,
                applied INTEGER NOT NULL DEFAULT 0,
                origin INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX oplog_db.idx_oplog_lww
                ON oplog(store_id, table_name, row_pk, hlc, device_id, op_id);
            CREATE INDEX oplog_db.idx_oplog_applied
                ON oplog(store_id, table_name, row_pk, applied, hlc, device_id, op_id);
            CREATE INDEX oplog_db.idx_oplog_store
                ON oplog(store_id, hlc, device_id, op_id);
            CREATE INDEX oplog_db.idx_oplog_origin
                ON oplog(device_id, hlc, op_id);
            CREATE TABLE oplog_db.oplog_arrivals (
                relay_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                op_id BLOB NOT NULL UNIQUE REFERENCES oplog(op_id) ON DELETE CASCADE,
                arrived_at INTEGER NOT NULL
            );
            CREATE TABLE oplog_db.oplog_heads (
                store_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_pk TEXT NOT NULL,
                hlc INTEGER NOT NULL,
                device_id BLOB NOT NULL,
                op_id BLOB NOT NULL,
                payload BLOB NOT NULL,
                origin_device BLOB,
                PRIMARY KEY (store_id, table_name, row_pk)
            );
            CREATE TABLE oplog_db.mesh_relay_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                stream_epoch BLOB NOT NULL,
                compacted_through_seq INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE oplog_db.mesh_peer_acks (
                peer_device_id BLOB PRIMARY KEY,
                stream_epoch BLOB NOT NULL,
                acked_relay_seq INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE oplog_db.mesh_origin_coverage (
                origin_device_id BLOB PRIMARY KEY,
                coverage BLOB NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO oplog_db.mesh_relay_state (singleton, stream_epoch, compacted_through_seq)
            VALUES (1, X'0101010101010101010101010101010101010101010101010101010101010101', 0);",
    )
    .unwrap();
    conn
}

#[test]
fn incremental_vacuum_reclaims_multiple_pages_in_one_call() {
    let dir = tempfile::tempdir().unwrap();
    let oplog_path = dir.path().join("oplog.db");
    let conn = Connection::open_in_memory().unwrap();
    conn.execute(
        "ATTACH DATABASE ?1 AS oplog_db",
        params![oplog_path.to_str().unwrap()],
    )
    .unwrap();
    conn.execute_batch(
        "PRAGMA oplog_db.auto_vacuum = INCREMENTAL;
             CREATE TABLE oplog_db.blob_test (id INTEGER PRIMARY KEY, data BLOB);",
    )
    .unwrap();
    let big = vec![0xABu8; 8192];
    for i in 0..200 {
        conn.execute(
            "INSERT INTO oplog_db.blob_test (id, data) VALUES (?1, ?2)",
            params![i, &big],
        )
        .unwrap();
    }
    conn.execute("DELETE FROM oplog_db.blob_test", []).unwrap();
    let free_before: i64 = conn
        .query_row("PRAGMA oplog_db.freelist_count", [], |r| r.get(0))
        .unwrap();
    assert!(
        free_before > 100,
        "expected >100 free pages, got {free_before}"
    );

    // Must reclaim many pages in a single call (previously execute_batch stopped at 1).
    let reclaimed = incremental_vacuum_oplog(&conn, 100).unwrap();
    assert!(
        reclaimed >= 50,
        "expected >=50 pages reclaimed in one call, got {reclaimed}"
    );
}

#[test]
fn compaction_scan_terminates_at_ceiling_without_wrapping() {
    let conn = setup_oplog_conn();
    let id = DeviceIdentity::generate();
    let now_secs = chrono::Utc::now().timestamp() as u64;
    for i in 1..=20u64 {
        let pk = format!("item-{i}");
        let op_payload = ProxyDbOp {
            table: "items".to_string(),
            key: vec![text_key("id", &pk)],
            mutation: Mutation::Upsert {
                columns: vec![text_col("id", &pk)],
            },
        }
        .encode_bytes()
        .unwrap();
        let signed = SignedOp::seal(
            OpBody {
                v: ENVELOPE_VERSION,
                hlc: Hlc((now_secs - 100 + i) << 32),
                device: id.device_id(),
                store: StoreId::new("proxydb").unwrap(),
                payload: op_payload,
            },
            &id,
        )
        .unwrap();
        oplog::append(&conn, &signed, "items", &pk, ORIGIN_LOCAL).unwrap();
    }
    // Resume at ceiling (15) with no rows in (15, 15]: must exhaust and return next_cursor=0
    // without wrapping back to 0 and re-scanning rows 1..15.
    let scan = compaction_candidates_with_lww(
        &conn,
        &CompactionPolicy::default(),
        0,
        15,
        std::time::Instant::now() + Duration::from_secs(5),
        15,
        CompactionProbeIndex::Applied,
    )
    .unwrap();
    assert_eq!(scan.next_cursor, 0);
    assert_eq!(scan.scanned, 0);
}

#[test]
fn wedged_peer_re_acking_same_seq_does_not_refresh_ttl_and_epoch_rotation_keeps_live_peer() {
    let conn = setup_oplog_conn();
    let local = DeviceIdentity::generate().device_id();
    let peer_wedged = DeviceIdentity::generate().device_id();
    let peer_live_rotated = DeviceIdentity::generate().device_id();
    let epoch = [1u8; 32];
    let now = chrono::Utc::now();
    let recent = now.to_rfc3339();
    let old_30d = (now - chrono::Duration::days(30)).to_rfc3339();

    // 1. Wedged peer: trusted, seen recently, acks seq=5, then backdate updated_at to 10d ago.
    conn.execute(
        "INSERT INTO devices (device_id, first_seen_at, last_seen_at, trusted)
             VALUES (?1, ?2, ?3, 1)",
        params![peer_wedged.to_hex(), &old_30d, &recent],
    )
    .unwrap();
    coverage::record_peer_ack(&conn, &peer_wedged, &epoch, 5).unwrap();
    conn.execute(
        "UPDATE oplog_db.mesh_peer_acks SET updated_at = datetime('now', '-10 days')
             WHERE peer_device_id = ?1",
        params![peer_wedged.as_bytes().as_slice()],
    )
    .unwrap();
    // Re-acking the SAME seq=5 must NOT refresh updated_at!
    coverage::record_peer_ack(&conn, &peer_wedged, &epoch, 5).unwrap();
    let cutoff_secs = now.timestamp() - PEER_ACK_TTL.as_secs() as i64;
    let dormant_before = (now - chrono::Duration::days(7)).to_rfc3339();
    let floor = coverage::min_peer_ack_with_ttl(
        &conn,
        &local,
        &epoch,
        Some(&dormant_before),
        Some(cutoff_secs),
    )
    .unwrap();
    assert_eq!(floor, None, "wedged peer must expire past PEER_ACK_TTL");

    // 2. Live long-standing peer (first_seen 30d ago, last_seen now) with NO current-epoch ack
    // (e.g. right after epoch rotation): must NOT be falsely classified dormant.
    conn.execute(
        "INSERT INTO devices (device_id, first_seen_at, last_seen_at, trusted)
             VALUES (?1, ?2, ?3, 1)",
        params![peer_live_rotated.to_hex(), &old_30d, &recent],
    )
    .unwrap();
    let floor_after_rotation = coverage::min_peer_ack_with_ttl(
        &conn,
        &local,
        &epoch,
        Some(&dormant_before),
        Some(cutoff_secs),
    )
    .unwrap();
    assert_eq!(
        floor_after_rotation,
        Some(0),
        "live peer missing current-epoch ack must pin at 0 until it re-acks"
    );
}

#[test]
fn bulk_table_upsert_head_omits_duplicate_payload_and_newest_op_resolves() {
    let conn = setup_oplog_conn();
    let id = DeviceIdentity::generate();
    let payload = ProxyDbOp {
        table: "items".to_string(),
        key: vec![text_key("id", "item-1")],
        mutation: Mutation::Upsert {
            columns: vec![
                text_col("id", "item-1"),
                text_col("content", "x".repeat(4096)),
            ],
        },
    }
    .encode_bytes()
    .unwrap();
    let signed = SignedOp::seal(
        OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(100 << 32),
            device: id.device_id(),
            store: StoreId::new("proxydb").unwrap(),
            payload: payload.clone(),
        },
        &id,
    )
    .unwrap();
    oplog::append(&conn, &signed, "items", "item-1", ORIGIN_LOCAL).unwrap();

    // oplog_heads.payload must be empty for bulk-table Upsert (no double storage).
    let head_payload: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM oplog_db.oplog_heads
                 WHERE store_id = 'proxydb' AND table_name = 'items' AND row_pk = 'item-1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        head_payload.is_empty(),
        "bulk table upsert head should store empty payload"
    );

    // newest_op_in_store must still resolve the full payload from oplog.envelope.
    let (_, resolved) = oplog::newest_op_in_store(
        &conn,
        "proxydb",
        "items",
        "item-1",
        &OpId::from_bytes([0; 32]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(resolved, payload);

    // Delete tombstone must still preserve full payload in oplog_heads.
    let del_payload = ProxyDbOp {
        table: "items".to_string(),
        key: vec![text_key("id", "item-1")],
        mutation: Mutation::Delete,
    }
    .encode_bytes()
    .unwrap();
    let del_signed = SignedOp::seal(
        OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(200 << 32),
            device: id.device_id(),
            store: StoreId::new("proxydb").unwrap(),
            payload: del_payload.clone(),
        },
        &id,
    )
    .unwrap();
    oplog::append(&conn, &del_signed, "items", "item-1", ORIGIN_LOCAL).unwrap();
    let del_head_payload: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM oplog_db.oplog_heads
                 WHERE store_id = 'proxydb' AND table_name = 'items' AND row_pk = 'item-1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(del_head_payload, del_payload);
}
