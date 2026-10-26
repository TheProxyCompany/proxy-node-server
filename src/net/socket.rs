//! The [`MeshPullSocket`] ("Female Socket") contract and reference [`OpLog`]
//! implementations (`ServeState` and [`OpLogPullSocket`]).

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use super::RelayCursorV2;
use super::server::ServeState;
use super::v3_client::unix_ms;
use crate::hlc::{Hlc, NodeClock};
use crate::identity::{DeviceId, DeviceIdentity};
use crate::log::{LogSource, OpLog, RelayStreamState, replay};
use crate::op::{OrderKey, SignedOp};
use crate::pull_v3::{CoverageVector, PullPageV3};
use crate::registry::{DeviceBook, DeviceRegistry};
use crate::store::Store;

/// Outcome of admitting a slice of relayed operations through a [`MeshPullSocket`].
#[derive(Debug)]
pub struct PullAdmission<E> {
    /// Leading ops (in input order) durably applied or deliberately skipped.
    pub admitted: usize,
    /// Leading ops before the first scope-skip, capped at `admitted`.
    pub claim_safe: usize,
    /// First admission/apply error encountered after the `admitted` prefix, if any.
    pub error: Option<E>,
}

/// The "Female Socket" contract that a host storage engine (such as Grand
/// Central's `proxy.db` + `oplog.db`) implements so `proxy-node-server` (the
/// "Male Plug") can drive Pull Protocol v3 page construction and client drains
/// without knowing the host's database or concurrency primitives.
pub trait MeshPullSocket {
    /// Host error type surfaced by storage and admission callbacks.
    type Error: std::fmt::Display;

    /// Construct a [`Self::Error`] for a protocol or verification violation.
    fn protocol_error(message: impl Into<String>) -> Self::Error;

    /// Construct a [`Self::Error`] for an invalid request argument (defaults to
    /// [`Self::protocol_error`]).
    fn invalid_argument(message: impl Into<String>) -> Self::Error {
        Self::protocol_error(message)
    }

    // ── Identity & Clock callbacks ──────────────────────────────────────

    /// Serving/pulling device's own [`DeviceId`]. Fronted on a fresh Channel A
    /// exchange so a peer's own emissions arrive ahead of transitive origins.
    fn own_device_id(&self) -> DeviceId {
        self.local_identity().device_id()
    }

    /// Local [`DeviceIdentity`] used to sign outgoing pull requests and pages.
    fn local_identity(&self) -> &DeviceIdentity {
        unimplemented!("MeshPullSocket::local_identity is required for signing")
    }

    /// Current Unix timestamp in milliseconds.
    fn now_ms(&self) -> i64 {
        unix_ms() as i64
    }

    /// Next [`Hlc`] timestamp used to seal outgoing envelopes.
    fn next_hlc(&self) -> Hlc {
        Hlc((self.now_ms().max(0) as u64) << 16)
    }

    // ── Server-side storage & auth callbacks ────────────────────────────

    /// Look up the stored 33-byte compressed SEC1 public key for `peer`.
    fn lookup_peer_sec1(&self, _peer: &DeviceId) -> Result<Option<[u8; 33]>, Self::Error> {
        Ok(None)
    }

    /// Whether `peer` is currently trusted to pull from this node.
    fn is_peer_trusted(&self, _peer: &DeviceId) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Whether per-origin coverage is primed and ready to serve/pull v3.
    fn is_coverage_primed(&self) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Current relay-local arrival stream epoch, head sequence, and compaction floor.
    fn relay_stream_state(&self) -> Result<RelayStreamState, Self::Error> {
        Err(Self::protocol_error(
            "MeshPullSocket::relay_stream_state is not implemented",
        ))
    }

    /// Every origin device present in the local op-log, ascending by raw
    /// 32-byte device id.
    fn origins(&self) -> Result<Vec<DeviceId>, Self::Error> {
        Ok(Vec::new())
    }

    /// One origin's `(OrderKey, raw_envelope_bytes)` rows strictly after `after`
    /// (`None` = from the beginning), ascending, optionally filtered to `store`,
    /// capped at `limit`.
    fn origin_since(
        &self,
        _origin: &DeviceId,
        _after: Option<OrderKey>,
        _store: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<(OrderKey, Vec<u8>)>, Self::Error> {
        Ok(Vec::new())
    }

    /// Relay-local arrival rows `(relay_seq, decoded_op, raw_envelope_bytes)`
    /// strictly after `after_seq` in arrival order, capped at `limit`.
    #[allow(clippy::type_complexity)]
    fn relay_since_with_envelopes(
        &self,
        _after_seq: u64,
        _limit: usize,
    ) -> Result<Vec<(u64, SignedOp, Vec<u8>)>, Self::Error> {
        Ok(Vec::new())
    }

    /// Record the channel-B cursor `peer` presented against `epoch` as a
    /// compaction acknowledgment.
    fn record_peer_ack(
        &self,
        _peer: &DeviceId,
        _epoch: &[u8; 32],
        _relay_after: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    // ── Client-side coverage, cursor & admission callbacks ──────────────

    /// This device's current per-origin high-water claims (`mesh_origin_coverage`).
    fn local_coverage(&self) -> Result<CoverageVector, Self::Error> {
        Ok(CoverageVector::default())
    }

    /// Known origin device ids used to construct inflated claims for a
    /// newest-first head-window preview (defaults to [`Self::origins`]).
    fn known_origins(&self) -> Result<Vec<DeviceId>, Self::Error> {
        self.origins()
    }

    /// Monotonically advance this device's local coverage claim for `origin` to
    /// `key` (called from inside the `admit_ops` quantum callback).
    fn advance_local_coverage(
        &self,
        _origin: &DeviceId,
        _key: OrderKey,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Monotonically persist `peer`'s relay cursor inside an already-acquired
    /// write quantum.
    fn save_relay_cursor(
        &self,
        _peer: &DeviceId,
        _cursor: RelayCursorV2,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Replace `peer`'s durable relay cursor on a validated stream reset.
    fn reset_relay_cursor(
        &self,
        _peer: &DeviceId,
        _cursor: RelayCursorV2,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Observe progress after one v3 page has been durably applied.
    fn on_v3_page_applied(
        &self,
        _peer: &DeviceId,
        _page: &PullPageV3,
        _pages: u64,
        _applied_total: usize,
    ) {
    }

    /// Acquire any host write gate / vouch fence and persist `cursor` for `peer`.
    fn commit_relay_cursor(
        &self,
        peer: &DeviceId,
        cursor: RelayCursorV2,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self: Sync,
    {
        async move { self.save_relay_cursor(peer, cursor) }
    }

    /// Acquire any host write gate / vouch fence and persist a validated v3
    /// stream reset for `peer`.
    fn commit_v3_reset(
        &self,
        peer: &DeviceId,
        reset: RelayCursorV2,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        Self: Sync,
    {
        async move { self.reset_relay_cursor(peer, reset) }
    }

    /// Verify, clock-check, scope-check, and durably apply `ops` relayed from
    /// `peer`, invoking `after_quantum(admitted_total, claim_safe_total)` after
    /// each bounded writer quantum while holding the host's write gate.
    fn admit_ops<F>(
        &self,
        _peer: &DeviceId,
        _ops: &[SignedOp],
        _skip_unattested: bool,
        _enforce_vouch: bool,
        _after_quantum: F,
    ) -> impl Future<Output = Result<PullAdmission<Self::Error>, Self::Error>> + Send
    where
        Self: Sync,
        F: FnMut(usize, usize) -> Result<(), Self::Error> + Send,
    {
        async {
            Err(Self::protocol_error(
                "MeshPullSocket::admit_ops is not implemented",
            ))
        }
    }
}

pub use MeshPullSocket as MeshPullHost;
pub use MeshPullSocket as PullStorage;

impl<L: LogSource, D: DeviceBook> MeshPullSocket for ServeState<L, D> {
    type Error = String;

    fn protocol_error(message: impl Into<String>) -> Self::Error {
        message.into()
    }

    fn own_device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    fn local_identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn lookup_peer_sec1(&self, peer: &DeviceId) -> Result<Option<[u8; 33]>, String> {
        self.relay_callers.try_key_for_device(peer)
    }

    fn relay_stream_state(&self) -> Result<RelayStreamState, String> {
        self.log
            .relay_state()?
            .ok_or_else(|| "relay stream is not supported by this log source".to_string())
    }

    fn origins(&self) -> Result<Vec<DeviceId>, String> {
        self.log.origins()
    }

    fn origin_since(
        &self,
        origin: &DeviceId,
        after: Option<OrderKey>,
        store: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(OrderKey, Vec<u8>)>, String> {
        self.log.origin_since(origin, after, store, limit)
    }

    fn relay_since_with_envelopes(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, SignedOp, Vec<u8>)>, String> {
        self.log
            .relay_since_with_envelopes(after_seq, limit)?
            .ok_or_else(|| "relay page is not supported by this log source".to_string())
    }
}

/// Reference in-memory [`MeshPullSocket`] implementation backed by [`OpLog`],
/// [`DeviceRegistry`], [`NodeClock`], and a [`Store`].
pub struct OpLogPullSocket<'a, S: Store> {
    pub identity: &'a DeviceIdentity,
    pub clock: &'a NodeClock,
    pub registry: &'a Mutex<DeviceRegistry>,
    pub log: &'a Mutex<OpLog>,
    pub store: &'a Mutex<S>,
    pub coverage: &'a Mutex<CoverageVector>,
    pub cursors: &'a Mutex<BTreeMap<DeviceId, RelayCursorV2>>,
}

impl<'a, S: Store + Send> MeshPullSocket for OpLogPullSocket<'a, S> {
    type Error = String;

    fn protocol_error(message: impl Into<String>) -> Self::Error {
        message.into()
    }

    fn local_identity(&self) -> &DeviceIdentity {
        self.identity
    }

    fn next_hlc(&self) -> Hlc {
        self.clock.now()
    }

    fn relay_stream_state(&self) -> Result<RelayStreamState, String> {
        Ok(self.log.lock().expect("oplog poisoned").relay_state())
    }

    fn origins(&self) -> Result<Vec<DeviceId>, String> {
        Ok(self.log.lock().expect("oplog poisoned").origins())
    }

    fn origin_since(
        &self,
        origin: &DeviceId,
        after: Option<OrderKey>,
        store: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(OrderKey, Vec<u8>)>, String> {
        self.log
            .lock()
            .expect("oplog poisoned")
            .origin_since(origin, after, store, limit)
    }

    fn relay_since_with_envelopes(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, SignedOp, Vec<u8>)>, String> {
        self.log
            .lock()
            .expect("oplog poisoned")
            .relay_since_with_envelopes(after_seq, limit)
    }

    fn local_coverage(&self) -> Result<CoverageVector, String> {
        Ok(self.coverage.lock().expect("coverage poisoned").clone())
    }

    fn known_origins(&self) -> Result<Vec<DeviceId>, String> {
        Ok(self
            .registry
            .lock()
            .expect("registry poisoned")
            .entries()
            .into_iter()
            .map(|(id, _)| id)
            .collect())
    }

    fn advance_local_coverage(&self, origin: &DeviceId, key: OrderKey) -> Result<(), String> {
        let mut cov = self.coverage.lock().expect("coverage poisoned");
        cov.0
            .entry(*origin)
            .and_modify(|existing| {
                if key > *existing {
                    *existing = key;
                }
            })
            .or_insert(key);
        Ok(())
    }

    fn save_relay_cursor(&self, peer: &DeviceId, cursor: RelayCursorV2) -> Result<(), String> {
        let mut cursors = self.cursors.lock().expect("cursors poisoned");
        cursors
            .entry(*peer)
            .and_modify(|existing| {
                if existing.epoch == cursor.epoch {
                    existing.after = existing.after.max(cursor.after);
                } else {
                    *existing = cursor;
                }
            })
            .or_insert(cursor);
        Ok(())
    }

    fn reset_relay_cursor(&self, peer: &DeviceId, cursor: RelayCursorV2) -> Result<(), String> {
        self.cursors
            .lock()
            .expect("cursors poisoned")
            .insert(*peer, cursor);
        Ok(())
    }

    fn admit_ops<F>(
        &self,
        _peer: &DeviceId,
        ops: &[SignedOp],
        skip_unattested: bool,
        _enforce_vouch: bool,
        mut after_quantum: F,
    ) -> impl Future<Output = Result<PullAdmission<String>, String>> + Send
    where
        Self: Sync,
        F: FnMut(usize, usize) -> Result<(), String> + Send,
    {
        let mut admitted = 0usize;
        let mut error = None;
        {
            let registry = self.registry.lock().expect("registry poisoned");
            let mut log = self.log.lock().expect("oplog poisoned");
            let mut store = self.store.lock().expect("store poisoned");
            let mut appended = false;
            for op in ops {
                let Some(verifying) = registry.key_for(&op.body.device) else {
                    if skip_unattested {
                        admitted += 1;
                        continue;
                    }
                    error = Some(format!(
                        "unknown signing device {}",
                        op.body.device.to_hex()
                    ));
                    break;
                };
                if let Err(e) = op.verify(verifying) {
                    error = Some(format!("verify op {}: {e}", op.id.to_hex()));
                    break;
                }
                if let Err(e) = self.clock.update(op.body.hlc, &op.body.device) {
                    error = Some(format!("clock update {}: {e}", op.id.to_hex()));
                    break;
                }
                if log.append(op.clone()) {
                    appended = true;
                }
                admitted += 1;
            }
            if appended {
                if let Err(e) = replay(&log, &mut *store) {
                    error = Some(format!("replay store: {e}"));
                }
            }
        }
        let cb_res = after_quantum(admitted, admitted);
        async move {
            cb_res?;
            Ok(PullAdmission {
                admitted,
                claim_safe: admitted,
                error,
            })
        }
    }
}
