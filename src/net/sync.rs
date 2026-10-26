//! Peer registration, key gossip, and incremental op-log sync rounds (v1 and
//! Relay v2).

use std::sync::Mutex;

use super::client::HttpPullSource;
use super::{DevicesResp, RelayCursorV2};
use crate::durable::OplogWriter;
use crate::error::TransportError;
use crate::hlc::NodeClock;
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::{OpLog, apply_range, replay};
use crate::op::OrderKey;
use crate::registry::DeviceRegistry;
use crate::store::Store;
use crate::transport::PullSource;

/// Fetch a peer's `/identity`, check its advertised device id against the key it
/// serves, register the key, and return the peer's device id plus whether this
/// call newly introduced the key.
pub async fn register_peer(
    source: &HttpPullSource,
    registry: &Mutex<DeviceRegistry>,
) -> Result<(DeviceId, bool), TransportError> {
    let (peer, _, newly_added) = register_peer_with_key(source, registry).await?;
    Ok((peer, newly_added))
}

/// Register a peer and retain the exact verified key for authenticated relay
/// requests.
pub async fn register_peer_with_key(
    source: &HttpPullSource,
    registry: &Mutex<DeviceRegistry>,
) -> Result<(DeviceId, [u8; 33], bool), TransportError> {
    let resp = source.fetch_identity().await?;
    let advertised = DeviceId::from_bytes(resp.device_id);
    let sec1: [u8; 33] = resp
        .public_key_sec1
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::Wire("public key is not 33 bytes".into()))?;
    let derived = DeviceIdentity::device_id_from_sec1(&sec1)?;
    if derived != advertised {
        return Err(TransportError::IdentityMismatch {
            advertised: advertised.to_hex(),
            derived: derived.to_hex(),
        });
    }
    let mut registry = registry.lock().expect("registry mutex poisoned");
    let newly_added = !registry.contains(&advertised);
    registry.insert_sec1(&sec1)?;
    Ok((advertised, sec1, newly_added))
}

/// Fetch a peer's `/devices` set and register every valid, not-yet-known key.
pub async fn learn_devices(
    source: &HttpPullSource,
    registry: &Mutex<DeviceRegistry>,
) -> Result<Vec<DeviceId>, TransportError> {
    let resp = source.fetch_devices().await?;
    Ok(learn_device_entries(resp, registry))
}

/// Authenticate a peer's exact `/devices` response with its pinned key before
/// admitting any advertised signer.
pub async fn learn_attested_devices(
    source: &HttpPullSource,
    expected_peer: DeviceId,
    expected_public_key_sec1: &[u8; 33],
    registry: &Mutex<DeviceRegistry>,
) -> Result<Vec<DeviceId>, TransportError> {
    let resp = source
        .fetch_attested_devices(expected_peer, expected_public_key_sec1)
        .await?;
    Ok(learn_device_entries(resp, registry))
}

fn learn_device_entries(resp: DevicesResp, registry: &Mutex<DeviceRegistry>) -> Vec<DeviceId> {
    let mut registry = registry.lock().expect("registry mutex poisoned");
    let mut added = Vec::new();
    for entry in resp.devices {
        let advertised = DeviceId::from_bytes(entry.device_id);
        let Ok(sec1) = <[u8; 33]>::try_from(entry.public_key_sec1.as_slice()) else {
            continue;
        };
        let Ok(derived) = DeviceIdentity::device_id_from_sec1(&sec1) else {
            continue;
        };
        if derived != advertised || registry.contains(&advertised) {
            continue;
        }
        if registry.insert_sec1(&sec1).is_ok() {
            added.push(advertised);
        }
    }
    added
}

/// How [`sync_once_with`] pushes newly-crossed ops into the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// Re-apply the whole log whenever the cursor moves.
    Replay,
    /// Apply only the ops the cursor newly crossed.
    Incremental,
}

/// One incremental pull from `source`, applying with [`ApplyMode::Replay`].
#[allow(clippy::too_many_arguments)]
pub async fn sync_once<S, P>(
    source: &P,
    registry: &Mutex<DeviceRegistry>,
    clock: &NodeClock,
    log: &Mutex<OpLog>,
    store: &Mutex<S>,
    cursor: &mut OrderKey,
    durability: Option<&Mutex<OplogWriter>>,
) -> Result<usize, TransportError>
where
    S: Store,
    P: PullSource<Error = TransportError>,
{
    sync_once_with(
        source,
        registry,
        clock,
        log,
        store,
        cursor,
        durability,
        ApplyMode::Replay,
    )
    .await
}

/// One incremental pull from `source`.
#[allow(clippy::too_many_arguments)]
pub async fn sync_once_with<S, P>(
    source: &P,
    registry: &Mutex<DeviceRegistry>,
    clock: &NodeClock,
    log: &Mutex<OpLog>,
    store: &Mutex<S>,
    cursor: &mut OrderKey,
    durability: Option<&Mutex<OplogWriter>>,
    mode: ApplyMode,
) -> Result<usize, TransportError>
where
    S: Store,
    P: PullSource<Error = TransportError>,
{
    let ops = source.pull(*cursor).await?;
    let mut appended = 0;
    let mut highest = *cursor;
    let mut abort: Option<TransportError> = None;
    {
        let registry = registry.lock().expect("registry mutex poisoned");
        let mut log = log.lock().expect("oplog mutex poisoned");
        for op in ops {
            let key = op.order_key();
            let Some(verifying) = registry.key_for(&op.body.device) else {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: "unknown device".into(),
                });
                break;
            };
            if let Err(e) = op.verify(verifying) {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: e.to_string(),
                });
                break;
            }
            if let Err(e) = clock.update(op.body.hlc, &op.body.device) {
                abort = Some(TransportError::Drift {
                    device: op.body.device.to_hex(),
                    hlc: op.body.hlc.0,
                    reason: e.to_string(),
                });
                break;
            }
            if !log.contains(&op.id) {
                if let Some(writer) = durability {
                    if let Err(e) = writer.lock().expect("oplog writer poisoned").append(&op) {
                        abort = Some(e.into());
                        break;
                    }
                }
                log.append(op.clone());
                appended += 1;
            }
            highest = key;
        }
    }
    if highest != *cursor {
        if let Some(writer) = durability {
            writer
                .lock()
                .expect("oplog writer poisoned")
                .sync_after_batch()?;
        }
    }
    if highest != *cursor {
        let log = log.lock().expect("oplog mutex poisoned");
        let mut store = store.lock().expect("store mutex poisoned");
        match mode {
            ApplyMode::Replay => {
                replay(&log, &mut *store).map_err(|e| TransportError::Replay(e.to_string()))?;
            }
            ApplyMode::Incremental => {
                apply_range(&log, &mut *store, *cursor, highest)
                    .map_err(|e| TransportError::Replay(e.to_string()))?;
            }
        }
    }
    *cursor = highest;
    match abort {
        Some(e) => Err(e),
        None => Ok(appended),
    }
}

/// Result of one authenticated insertion-order relay pull.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelaySyncOutcome {
    /// Entries whose embedded operation signature and clock were accepted.
    pub received: usize,
    /// Accepted operations that were not already in the local log.
    pub appended: usize,
    /// The peer authenticated a different stream epoch or retention floor.
    pub reset: bool,
}

/// Pull one authenticated relay-v2 page from a pinned peer.
#[allow(clippy::too_many_arguments)]
pub async fn sync_relay_once_v2<S>(
    source: &HttpPullSource,
    local_identity: &DeviceIdentity,
    expected_peer: DeviceId,
    expected_public_key_sec1: &[u8; 33],
    registry: &Mutex<DeviceRegistry>,
    clock: &NodeClock,
    log: &Mutex<OpLog>,
    store: &Mutex<S>,
    cursor: &mut RelayCursorV2,
    durability: Option<&Mutex<OplogWriter>>,
) -> Result<RelaySyncOutcome, TransportError>
where
    S: Store,
{
    let page = source
        .fetch_relay_ops_v2(
            local_identity,
            expected_peer,
            expected_public_key_sec1,
            *cursor,
        )
        .await?;
    if page.reset {
        *cursor = page.cursor();
        return Ok(RelaySyncOutcome {
            reset: true,
            ..RelaySyncOutcome::default()
        });
    }

    let initial = *cursor;
    let mut after = initial.after;
    let mut received = 0;
    let mut appended = 0;
    let mut abort = None;
    {
        let registry = registry.lock().expect("registry mutex poisoned");
        let mut log = log.lock().expect("oplog mutex poisoned");
        for entry in page.entries {
            let op = entry.op;
            let Some(verifying) = registry.key_for(&op.body.device) else {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: "unknown device".into(),
                });
                break;
            };
            if let Err(e) = op.verify(verifying) {
                abort = Some(TransportError::Verify {
                    device: op.body.device.to_hex(),
                    reason: e.to_string(),
                });
                break;
            }
            if let Err(e) = clock.update(op.body.hlc, &op.body.device) {
                abort = Some(TransportError::Drift {
                    device: op.body.device.to_hex(),
                    hlc: op.body.hlc.0,
                    reason: e.to_string(),
                });
                break;
            }
            if !log.contains(&op.id) {
                if let Some(writer) = durability {
                    if let Err(e) = writer.lock().expect("oplog writer poisoned").append(&op) {
                        abort = Some(e.into());
                        break;
                    }
                }
                log.append(op);
                appended += 1;
            }
            after = entry.seq;
            received += 1;
        }
    }

    if after != initial.after {
        if let Some(writer) = durability {
            writer
                .lock()
                .expect("oplog writer poisoned")
                .sync_after_batch()?;
        }
        let log = log.lock().expect("oplog mutex poisoned");
        let mut store = store.lock().expect("store mutex poisoned");
        replay(&log, &mut *store).map_err(|e| TransportError::Replay(e.to_string()))?;
    }
    *cursor = RelayCursorV2 {
        epoch: page.epoch,
        after,
    };
    match abort {
        Some(error) => Err(error),
        None => Ok(RelaySyncOutcome {
            received,
            appended,
            reset: false,
        }),
    }
}
