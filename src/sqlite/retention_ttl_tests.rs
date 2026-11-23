//! The peer ack TTL decides when a silent peer stops pinning `ack_floor`.

use std::time::Duration;

use rusqlite::{Connection, params};

use super::retention::{PEER_ACK_TTL, safe_relay_floor, safe_relay_floor_with_ttl};
use crate::DeviceId;

const HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const HOUR: u64 = 60 * 60;

/// Ten ops that arrived ten days ago, and one trusted peer that was seen just
/// now but last acknowledged relay position 3 two hours ago.
fn log_with_a_two_hour_old_ack() -> (Connection, DeviceId) {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "ATTACH DATABASE ':memory:' AS oplog_db;
         CREATE TABLE devices (
             device_id TEXT PRIMARY KEY,
             trusted INTEGER NOT NULL,
             introduced_by TEXT,
             first_seen_at TEXT NOT NULL,
             last_seen_at TEXT NOT NULL
         );
         CREATE TABLE oplog_db.mesh_relay_state (
             singleton INTEGER PRIMARY KEY,
             stream_epoch BLOB NOT NULL
         );
         CREATE TABLE oplog_db.oplog_arrivals (
             relay_seq INTEGER PRIMARY KEY,
             arrived_at INTEGER NOT NULL
         );
         CREATE TABLE oplog_db.mesh_peer_acks (
             peer_device_id BLOB PRIMARY KEY,
             stream_epoch BLOB NOT NULL,
             acked_relay_seq INTEGER NOT NULL,
             updated_at TEXT NOT NULL
         );",
    )
    .unwrap();
    let epoch = [0x5A_u8; 32];
    let peer = DeviceId::from_bytes([0xBB; 32]);
    let now = chrono::Utc::now();
    conn.execute(
        "INSERT INTO oplog_db.mesh_relay_state (singleton, stream_epoch) VALUES (1, ?1)",
        params![epoch.as_slice()],
    )
    .unwrap();
    let arrived_at = now.timestamp() - 10 * 24 * HOUR as i64;
    for relay_seq in 1..=10 {
        conn.execute(
            "INSERT INTO oplog_db.oplog_arrivals (relay_seq, arrived_at) VALUES (?1, ?2)",
            params![relay_seq, arrived_at],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO devices (device_id, trusted, first_seen_at, last_seen_at)
         VALUES (?1, 1, ?2, ?2)",
        params![peer.to_hex(), now.to_rfc3339()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oplog_db.mesh_peer_acks
             (peer_device_id, stream_epoch, acked_relay_seq, updated_at)
         VALUES (?1, ?2, 3, datetime('now', '-2 hours'))",
        params![peer.as_bytes().as_slice(), epoch.as_slice()],
    )
    .unwrap();
    (conn, DeviceId::from_bytes([0xAA; 32]))
}

#[test]
fn an_ack_inside_the_ttl_pins_the_floor_and_one_past_it_does_not() {
    let (conn, local) = log_with_a_two_hour_old_ack();

    let pinned =
        safe_relay_floor_with_ttl(&conn, &local, HORIZON, Duration::from_secs(3 * HOUR)).unwrap();
    assert_eq!(pinned.horizon_floor, 10);
    assert_eq!(pinned.ack_floor, 3);
    assert_eq!(pinned.safe_floor, 3);

    let released =
        safe_relay_floor_with_ttl(&conn, &local, HORIZON, Duration::from_secs(HOUR)).unwrap();
    assert_eq!(released.horizon_floor, 10);
    assert_eq!(released.ack_floor, 0);
    assert_eq!(released.safe_floor, 10);
}

#[test]
fn the_default_floor_uses_the_seven_day_ttl() {
    let (conn, local) = log_with_a_two_hour_old_ack();

    let default = safe_relay_floor(&conn, &local, HORIZON).unwrap();
    let explicit = safe_relay_floor_with_ttl(&conn, &local, HORIZON, PEER_ACK_TTL).unwrap();
    assert_eq!(default.safe_floor, 3);
    assert_eq!(explicit.safe_floor, default.safe_floor);
    assert_eq!(explicit.ack_floor, default.ack_floor);
}
