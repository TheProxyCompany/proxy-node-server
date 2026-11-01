//! SQLite-backed [`MeshPullSocket`] server implementation over `oplog_db` and `main.devices`.

use rusqlite::OptionalExtension;

use super::SqliteError;
use super::{coverage, oplog};
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::RelayStreamState;
use crate::net::MeshPullSocket;
use crate::op::{OrderKey, SignedOp};

/// Server-side [`MeshPullSocket`] backed by a SQLite connection with `oplog_db` attached.
pub struct SqlitePullServerSocket<'a> {
    pub conn: &'a rusqlite::Connection,
    pub identity: &'a DeviceIdentity,
}

impl<'a> SqlitePullServerSocket<'a> {
    pub fn new(conn: &'a rusqlite::Connection, identity: &'a DeviceIdentity) -> Self {
        Self { conn, identity }
    }
}

impl MeshPullSocket for SqlitePullServerSocket<'_> {
    type Error = SqliteError;

    fn protocol_error(message: impl Into<String>) -> Self::Error {
        SqliteError::Other(message.into())
    }

    fn invalid_argument(message: impl Into<String>) -> Self::Error {
        SqliteError::InvalidArgument(message.into())
    }

    fn own_device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    fn local_identity(&self) -> &DeviceIdentity {
        self.identity
    }

    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, SqliteError> {
        let hex = peer.to_hex();
        let key: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT COALESCE(
                     (SELECT public_key FROM devices
                      WHERE device_id = ?1 AND public_key IS NOT NULL),
                     (SELECT public_key FROM device_vouches
                      WHERE device_id = ?1
                      ORDER BY updated_at DESC, voucher_device_id ASC
                      LIMIT 1)
                 )",
                [&hex],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| SqliteError::Other(format!("lookup peer verifying key: {e}")))?;
        Ok(key.and_then(|bytes| <[u8; 33]>::try_from(bytes.as_slice()).ok()))
    }

    fn is_peer_trusted(&self, peer: &DeviceId) -> Result<bool, SqliteError> {
        let hex = peer.to_hex();
        let trusted: Option<i64> = self
            .conn
            .query_row(
                "SELECT CASE
                     WHEN EXISTS (
                         SELECT 1 FROM device_retirements WHERE device_id = ?1
                     ) THEN 0
                     WHEN EXISTS (
                         SELECT 1 FROM devices
                         WHERE device_id = ?1 AND trusted = 1 AND public_key IS NOT NULL
                     ) THEN 1
                     WHEN EXISTS (
                         SELECT 1 FROM device_vouches AS vouch
                         JOIN devices AS voucher
                           ON voucher.device_id = vouch.voucher_device_id
                         WHERE vouch.device_id = ?1
                           AND voucher.trusted = 1
                           AND voucher.public_key IS NOT NULL
                           AND NOT EXISTS (
                               SELECT 1 FROM device_retirements
                               WHERE device_retirements.device_id = voucher.device_id
                           )
                     ) THEN 1
                     ELSE 0
                 END",
                [&hex],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| SqliteError::Other(format!("check peer trust: {e}")))?;
        Ok(trusted.unwrap_or(0) != 0)
    }

    fn is_coverage_primed(&self) -> Result<bool, SqliteError> {
        coverage::is_primed(self.conn)
    }

    fn relay_stream_state(&self) -> Result<RelayStreamState, SqliteError> {
        let stream = oplog::relay_stream_state(self.conn)?;
        Ok(RelayStreamState {
            epoch: stream.stream_epoch,
            head: stream.head_seq,
            floor: stream.compacted_through_seq,
        })
    }

    fn origins(&self) -> Result<Vec<DeviceId>, SqliteError> {
        coverage::origins(self.conn)
    }

    fn origin_since(
        &self,
        origin: &DeviceId,
        after: Option<OrderKey>,
        store: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(OrderKey, Vec<u8>)>, SqliteError> {
        oplog::origin_since(self.conn, origin, after, store, limit)
    }

    fn relay_since_with_envelopes(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, SignedOp, Vec<u8>)>, SqliteError> {
        oplog::relay_since_with_envelopes(self.conn, after_seq, limit)
    }

    fn record_peer_ack(
        &self,
        peer: &DeviceId,
        epoch: &[u8; 32],
        relay_after: u64,
    ) -> Result<(), SqliteError> {
        coverage::record_peer_ack(self.conn, peer, epoch, relay_after)
    }
}
