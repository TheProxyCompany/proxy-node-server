//! SQLite-backed device key registry and `/devices` gossip verification.

use crate::net::DeviceEntry;
use crate::{DeviceId, DeviceIdentity, DeviceRegistry};

use super::SqliteError as GCError;

/// Every globally trusted row, plus keys learned from a peer-signed manifest.
pub fn relayable_keyed_devices(
    conn: &rusqlite::Connection,
) -> Result<Vec<(DeviceId, [u8; 33])>, GCError> {
    let mut stmt = conn
        .prepare(
            "SELECT device_id, public_key
             FROM devices
             WHERE public_key IS NOT NULL AND trusted = 1
             UNION
             SELECT vouched_device_id, public_key FROM device_vouches",
        )
        .map_err(|e| GCError::Other(format!("device book prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| GCError::Other(format!("device book query: {e}")))?;

    let mut devices = Vec::new();
    for row in rows {
        let (id_hex, key) = row.map_err(|e| GCError::Other(format!("device book row: {e}")))?;
        let (Ok(id), Ok(sec1)) = (
            DeviceId::from_hex(&id_hex),
            <[u8; 33]>::try_from(key.as_slice()),
        ) else {
            continue;
        };
        if DeviceIdentity::device_id_from_sec1(&sec1).is_ok_and(|derived| derived == id) {
            devices.push((id, sec1));
        }
    }
    Ok(devices)
}

/// Load trusted device keys (plus optional voucher-scoped keys) from `devices`.
pub fn registry_keyed_devices(
    conn: &rusqlite::Connection,
    voucher: Option<&str>,
) -> Result<Vec<(DeviceId, [u8; 33])>, GCError> {
    let sql = if voucher.is_some() {
        "SELECT device_id, public_key
         FROM devices
         WHERE public_key IS NOT NULL AND trusted = 1
         UNION
         SELECT vouched_device_id, public_key
         FROM device_vouches WHERE voucher_device_id = ?1"
    } else {
        "SELECT device_id, public_key
         FROM devices
         WHERE public_key IS NOT NULL AND trusted = 1"
    };
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| GCError::Other(format!("device registry prepare: {e}")))?;
    let collect_row =
        |row: &rusqlite::Row<'_>| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?));
    let rows = match voucher {
        Some(voucher) => stmt.query_map(rusqlite::params![voucher], collect_row),
        None => stmt.query_map([], collect_row),
    }
    .map_err(|e| GCError::Other(format!("device registry query: {e}")))?;

    let mut devices = Vec::new();
    for row in rows {
        let (id_hex, key) = row.map_err(|e| GCError::Other(format!("device registry row: {e}")))?;
        let (Ok(id), Ok(sec1)) = (
            DeviceId::from_hex(&id_hex),
            <[u8; 33]>::try_from(key.as_slice()),
        ) else {
            continue;
        };
        if DeviceIdentity::device_id_from_sec1(&sec1).is_ok_and(|derived| derived == id) {
            devices.push((id, sec1));
        }
    }
    Ok(devices)
}

pub fn load_registry_conn(
    conn: &rusqlite::Connection,
    voucher: Option<&str>,
) -> Result<DeviceRegistry, GCError> {
    let mut registry = DeviceRegistry::new();
    for (_, sec1) in registry_keyed_devices(conn, voucher)? {
        let _ = registry.insert_sec1(&sec1);
    }
    Ok(registry)
}

/// Filter a `/devices` payload down to entries whose compressed SEC1 public key
/// derives their advertised 32-byte `DeviceId`.
#[cfg(feature = "pull-http")]
pub fn verified_device_entries(entries: &[DeviceEntry]) -> Vec<(String, [u8; 33])> {
    let mut valid = Vec::new();
    for entry in entries {
        let advertised = DeviceId::from_bytes(entry.device_id);
        let Ok(sec1) = <[u8; 33]>::try_from(entry.public_key_sec1.as_slice()) else {
            continue;
        };
        let Ok(derived) = DeviceIdentity::device_id_from_sec1(&sec1) else {
            continue;
        };
        if derived == advertised {
            valid.push((advertised.to_hex(), sec1));
        }
    }
    valid
}
