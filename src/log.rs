//! Op-log engine: an append-only, HLC-ordered set of signed ops with dedup by
//! content id. The reference impl is in-memory; the shape lets Grand Central
//! back it with proxy.db.

use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use crate::error::ReplayError;
use crate::op::{OpId, OrderKey, SignedOp};
use crate::store::{OpContext, Store};

/// An append-only, totally-ordered set of signed ops, keyed by the full
/// `(hlc, device, op_id)` order key so two distinct ops never overwrite each
/// other.
#[derive(Default)]
pub struct OpLog {
    ops: BTreeMap<OrderKey, SignedOp>,
    ids: HashSet<OpId>,
}

impl OpLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert, deduplicating by `OpId`. Returns true if the op was new.
    /// Signature verification is the caller's responsibility (it needs the
    /// device registry).
    pub fn append(&mut self, op: SignedOp) -> bool {
        if !self.ids.insert(op.id) {
            return false;
        }
        self.ops.insert(op.order_key(), op);
        true
    }

    /// Whether an op with this id is already in the log. Lets a caller order a
    /// durable write BEFORE the in-memory insert without a failed durable write
    /// leaving a memory-only op behind.
    pub fn contains(&self, id: &OpId) -> bool {
        self.ids.contains(id)
    }

    /// All ops in global total order.
    pub fn iter(&self) -> impl Iterator<Item = &SignedOp> {
        self.ops.values()
    }

    /// Ops strictly greater than `cursor` in the total order, in order. The
    /// pull-loop increment (phase 1). Strict-greater on the full order key means
    /// an op tying the cursor's HLC is never skipped.
    pub fn since(&self, cursor: OrderKey) -> impl Iterator<Item = &SignedOp> {
        self.ops
            .range((Bound::Excluded(cursor), Bound::Unbounded))
            .map(|(_, op)| op)
    }

    /// Highest order key currently held, if any. Doubles as the resume cursor.
    pub fn head(&self) -> Option<OrderKey> {
        self.ops.keys().next_back().copied()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Decode and apply every op targeting `store` in global total order.
pub fn replay<S: Store>(log: &OpLog, store: &mut S) -> Result<(), ReplayError<S::Error>> {
    apply_ops(log.iter(), store)
}

/// Apply just the ops in `(after, through]` — the range a pull batch newly
/// crossed — to `store`, in total order. The incremental counterpart to
/// [`replay`]: it touches only the batch's ops, so a large log is never
/// re-applied on every sync (the G1 seam Grand Central's proxy.db adapter needs;
/// whole-log [`replay`] is O(history) per pull).
///
/// The store must satisfy the [`Store`] idempotency contract and enforce its own
/// per-row conflict order (e.g. HLC last-write-wins): the range is not re-sorted
/// against already-applied history, and a retry after a failed durability fsync
/// can re-present ops the store already saw. The reference [`crate::kv::KvStore`]
/// resolves by arrival order and so is replayed whole; a store with an internal
/// version guard uses this path.
pub fn apply_range<S: Store>(
    log: &OpLog,
    store: &mut S,
    after: OrderKey,
    through: OrderKey,
) -> Result<(), ReplayError<S::Error>> {
    apply_ops(
        log.since(after).take_while(|op| op.order_key() <= through),
        store,
    )
}

fn apply_ops<'a, S: Store>(
    ops: impl Iterator<Item = &'a SignedOp>,
    store: &mut S,
) -> Result<(), ReplayError<S::Error>> {
    let store_id = store.store_id();
    for op in ops {
        if op.body.store != store_id {
            continue;
        }
        let native = store.decode(&op.body.payload).map_err(ReplayError::Store)?;
        let ctx = OpContext {
            op_id: op.id,
            order_key: op.order_key(),
            hlc: op.body.hlc,
            device: &op.body.device,
        };
        store.apply(ctx, native).map_err(ReplayError::Store)?;
    }
    Ok(())
}

/// Read-only view of an op-log the pull server serves from: total-order paging,
/// the head cursor, and a dedup probe. The reference [`OpLog`] satisfies it
/// behind an `Arc<Mutex<..>>`; Grand Central implements it over the `oplog`
/// SQL table (the G2 seam) so [`crate::net::router`] serves either without
/// knowing which. `Clone` because it is held in axum state.
pub trait LogSource: Clone + Send + Sync + 'static {
    /// Ops strictly after `cursor` in total order, capped at `limit`.
    fn since(&self, cursor: OrderKey, limit: usize) -> Vec<SignedOp>;
    /// Highest order key held, if any.
    fn head(&self) -> Option<OrderKey>;
    /// Whether an op with this id is already present.
    fn contains(&self, id: &OpId) -> bool;
}

impl LogSource for Arc<Mutex<OpLog>> {
    fn since(&self, cursor: OrderKey, limit: usize) -> Vec<SignedOp> {
        self.lock()
            .expect("oplog mutex poisoned")
            .since(cursor)
            .take(limit)
            .cloned()
            .collect()
    }

    fn head(&self) -> Option<OrderKey> {
        self.lock().expect("oplog mutex poisoned").head()
    }

    fn contains(&self, id: &OpId) -> bool {
        self.lock().expect("oplog mutex poisoned").contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::identity::DeviceIdentity;
    use crate::op::{ENVELOPE_VERSION, OpBody, StoreId};

    fn op_with(id: &DeviceIdentity, hlc: u64, payload: Vec<u8>) -> SignedOp {
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(hlc),
            device: id.device_id(),
            store: StoreId::new("kv").unwrap(),
            payload,
        };
        SignedOp::seal(body, id).unwrap()
    }

    fn op_at(id: &DeviceIdentity, hlc: u64) -> SignedOp {
        op_with(id, hlc, vec![hlc as u8])
    }

    #[test]
    fn append_dedups_by_id() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        let op = op_at(&id, 10);
        assert!(log.append(op.clone()));
        assert!(!log.append(op));
        assert_eq!(log.len(), 1);
    }

    // Regression, finding 1: two distinct ops from one device at the same HLC
    // must both survive; keying by HLC+device alone silently dropped one.
    #[test]
    fn distinct_ops_at_same_hlc_and_device_both_retained() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        let a = op_with(&id, 10, vec![0xaa]);
        let b = op_with(&id, 10, vec![0xbb]);
        assert_ne!(a.id, b.id);
        assert!(log.append(a.clone()));
        assert!(log.append(b.clone()));
        assert_eq!(log.len(), 2);

        let ids: HashSet<OpId> = log.iter().map(|o| o.id).collect();
        assert!(ids.contains(&a.id));
        assert!(ids.contains(&b.id));
    }

    #[test]
    fn iter_is_ordered_regardless_of_insertion_order() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        log.append(op_at(&id, 30));
        log.append(op_at(&id, 10));
        log.append(op_at(&id, 25));
        log.append(op_at(&id, 21));

        let order: Vec<Hlc> = log.iter().map(|o| o.body.hlc).collect();
        assert_eq!(order, vec![Hlc(10), Hlc(21), Hlc(25), Hlc(30)]);
    }

    #[test]
    fn since_and_head() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        assert_eq!(log.head(), None);
        let first = op_at(&id, 10);
        log.append(first.clone());
        log.append(op_at(&id, 20));
        log.append(op_at(&id, 30));

        assert_eq!(log.head().map(|k| k.hlc.0), Some(30));
        let after: Vec<u64> = log.since(first.order_key()).map(|o| o.body.hlc.0).collect();
        assert_eq!(after, vec![20, 30]);
    }

    // Regression, finding 2: a second op tying the cursor's HLC must not be
    // skipped. With an HLC-only cursor, `hlc > cursor` dropped every op sharing
    // the cursor's HLC; the full order key resumes strictly after just the one.
    #[test]
    fn since_does_not_skip_ops_tying_cursor_hlc() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        let a = op_with(&id, 10, vec![0x01]);
        let b = op_with(&id, 10, vec![0x02]);
        log.append(a.clone());
        log.append(b.clone());
        log.append(op_at(&id, 20));

        // Resume after whichever op sorts first; its same-HLC sibling must still
        // come back.
        let (lo, hi) = if a.order_key() < b.order_key() {
            (a, b)
        } else {
            (b, a)
        };
        let resumed: Vec<OpId> = log.since(lo.order_key()).map(|o| o.id).collect();
        assert!(resumed.contains(&hi.id), "sibling at tied HLC was skipped");
        assert_eq!(resumed.len(), 2);
    }

    // apply_range applies only the newly-crossed window, in order, so the last
    // write in that window wins — matching replay over the same range without
    // re-touching earlier history.
    #[test]
    fn apply_range_applies_only_the_crossed_window() {
        use crate::kv::{KvOp, KvStore};

        let id = DeviceIdentity::generate();
        let template = KvStore::new();
        let seal = |hlc: u64, key: &str, val: &[u8]| {
            let payload = template
                .encode(&KvOp::Put {
                    key: key.into(),
                    value: val.to_vec(),
                })
                .unwrap();
            let body = OpBody {
                v: ENVELOPE_VERSION,
                hlc: Hlc(hlc),
                device: id.device_id(),
                store: crate::kv::kv_store_id(),
                payload,
            };
            SignedOp::seal(body, &id).unwrap()
        };

        let mut log = OpLog::new();
        let o10 = seal(10, "k", b"first");
        let o20 = seal(20, "k", b"second");
        let o30 = seal(30, "k", b"third");
        log.append(o10.clone());
        log.append(o20.clone());
        log.append(o30.clone());

        // Apply only (o10, o30]: o20 then o30, so "third" wins; o10 is untouched.
        let mut store = KvStore::new();
        apply_range(&log, &mut store, o10.order_key(), o30.order_key()).unwrap();
        assert_eq!(store.get("k"), Some(&b"third"[..]));

        // Range excludes the head: only o20 is applied.
        let mut store = KvStore::new();
        apply_range(&log, &mut store, o10.order_key(), o20.order_key()).unwrap();
        assert_eq!(store.get("k"), Some(&b"second"[..]));
    }
}
