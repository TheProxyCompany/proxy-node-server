//! Bounded keyset scan of arrival-less `oplog_db.oplog` rows eligible for
//! horizon compaction (for example after revoked or demoted signer relay pruning).

use crate::{DeviceId, Hlc, OpId, OrderKey};
use rusqlite::params;

use super::SqliteError as GCError;
use super::retention::CompactionPolicy;
use super::retention_pins::{PinState, is_candidate_pinned, store_head_op_ids};

pub struct OrphanOplogScan {
    pub candidates: Vec<(OpId, i64)>,
    pub next_cursor: Vec<u8>,
    pub scanned: usize,
}

/// Bounded scan of `oplog_db.oplog` rows that have no `oplog_arrivals` entry
/// and whose HLC lies at or below `horizon_hlc_max`. Rides `idx_oplog_order`
/// (72-byte `OrderKey` wire cursor) when present, falling back to
/// `PRIMARY KEY(op_id)` (32-byte cursor).
pub fn orphan_oplog_candidates(
    conn: &rusqlite::Connection,
    policy: &CompactionPolicy,
    horizon_hlc_max: i64,
    max_candidates: usize,
    deadline: std::time::Instant,
    after_cursor: &[u8],
) -> Result<OrphanOplogScan, GCError> {
    if horizon_hlc_max <= 0 || max_candidates == 0 || policy.candidate_scan_cap == 0 {
        return Ok(OrphanOplogScan {
            candidates: Vec::new(),
            next_cursor: Vec::new(),
            scanned: 0,
        });
    }
    let pins = PinState::detect(conn)?;
    let store_heads = store_head_op_ids(conn, &pins.tables)?;

    const PAGE: usize = 2048;
    let scan_cap = policy.candidate_scan_cap.max(PAGE);
    let mut candidates = Vec::new();
    let mut scanned = 0usize;
    let mut exhausted = false;

    if pins.tables.idx_oplog_order {
        let mut cursor_key = <[u8; 72]>::try_from(after_cursor)
            .map(|wire| OrderKey::from_wire(&wire))
            .unwrap_or(OrderKey {
                hlc: Hlc(0),
                device: DeviceId::from_bytes([0; 32]),
                op_id: OpId::from_bytes([0; 32]),
            });
        while candidates.len() < max_candidates
            && scanned < scan_cap
            && std::time::Instant::now() < deadline
        {
            let rows = conn
                .prepare_cached(
                    "SELECT o.hlc, o.device_id, o.op_id, o.store_id, o.table_name, o.row_pk,
                            o.applied, (a.op_id IS NULL)
                     FROM oplog_db.oplog AS o INDEXED BY idx_oplog_order
                     LEFT JOIN oplog_db.oplog_arrivals AS a ON a.op_id = o.op_id
                     WHERE o.hlc >= 0 AND o.hlc <= ?1
                       AND (o.hlc, o.device_id, o.op_id) > (?2, ?3, ?4)
                     ORDER BY o.hlc, o.device_id, o.op_id
                     LIMIT ?5",
                )
                .map_err(|e| GCError::Other(format!("orphan oplog order scan prepare: {e}")))?
                .query_map(
                    params![
                        horizon_hlc_max,
                        cursor_key.hlc.0 as i64,
                        cursor_key.device.as_bytes().as_slice(),
                        cursor_key.op_id.as_bytes().as_slice(),
                        PAGE as i64,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, bool>(7)?,
                        ))
                    },
                )
                .map_err(|e| GCError::Other(format!("orphan oplog order scan: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GCError::Other(format!("orphan oplog order row: {e}")))?;
            if rows.is_empty() {
                exhausted = true;
                break;
            }
            for (hlc, dev, op_id, store, table, row_pk, applied, arrival_missing) in rows {
                scanned += 1;
                let (Ok(dev_arr), Ok(op_arr)) = (
                    <[u8; 32]>::try_from(dev.as_slice()),
                    <[u8; 32]>::try_from(op_id.as_slice()),
                ) else {
                    continue;
                };
                cursor_key = OrderKey {
                    hlc: Hlc(hlc as u64),
                    device: DeviceId::from_bytes(dev_arr),
                    op_id: OpId::from_bytes(op_arr),
                };
                if !arrival_missing || applied != 1 || store_heads.contains(&op_arr) {
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    break;
                }
                if is_candidate_pinned(conn, &pins, &op_id, &store, &table, &row_pk)? {
                    continue;
                }
                candidates.push((OpId::from_bytes(op_arr), 0));
                if candidates.len() >= max_candidates {
                    break;
                }
            }
        }
        return Ok(OrphanOplogScan {
            candidates,
            next_cursor: if exhausted {
                Vec::new()
            } else {
                cursor_key.to_wire().to_vec()
            },
            scanned,
        });
    }

    let mut cursor = if after_cursor.len() == 32 {
        after_cursor.to_vec()
    } else {
        Vec::new()
    };
    while candidates.len() < max_candidates
        && scanned < scan_cap
        && std::time::Instant::now() < deadline
    {
        let rows = conn
            .prepare_cached(
                "SELECT o.op_id, o.hlc, o.store_id, o.table_name, o.row_pk,
                        o.applied, (a.op_id IS NULL)
                 FROM oplog_db.oplog AS o
                 LEFT JOIN oplog_db.oplog_arrivals AS a ON a.op_id = o.op_id
                 WHERE o.op_id > ?1
                 ORDER BY o.op_id
                 LIMIT ?2",
            )
            .map_err(|e| GCError::Other(format!("orphan oplog pk scan prepare: {e}")))?
            .query_map(params![cursor.as_slice(), PAGE as i64], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })
            .map_err(|e| GCError::Other(format!("orphan oplog pk scan: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| GCError::Other(format!("orphan oplog pk row: {e}")))?;
        if rows.is_empty() {
            exhausted = true;
            break;
        }
        for (op_id, hlc, store, table, row_pk, applied, arrival_missing) in rows {
            scanned += 1;
            cursor.clone_from(&op_id);
            let Ok(op_arr) = <[u8; 32]>::try_from(op_id.as_slice()) else {
                continue;
            };
            if !arrival_missing
                || applied != 1
                || hlc < 0
                || hlc > horizon_hlc_max
                || store_heads.contains(&op_arr)
            {
                continue;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            if is_candidate_pinned(conn, &pins, &op_id, &store, &table, &row_pk)? {
                continue;
            }
            candidates.push((OpId::from_bytes(op_arr), 0));
            if candidates.len() >= max_candidates {
                break;
            }
        }
    }
    Ok(OrphanOplogScan {
        candidates,
        next_cursor: if exhausted { Vec::new() } else { cursor },
        scanned,
    })
}
