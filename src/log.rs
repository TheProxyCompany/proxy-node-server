//! Op-log engine: an append-only, HLC-ordered set of signed ops with dedup by
//! content id. The reference impl is in-memory; the shape lets Grand Central
//! back it with proxy.db.

use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};

use crate::error::ReplayError;
use crate::op::{OpId, OrderKey, SignedOp};
use crate::store::{OpContext, Store};

/// Durable identity and bounds of one relay-local arrival stream. `epoch`
/// changes whenever a stream cannot safely continue its prior sequence space;
/// `floor` is the greatest sequence no longer available, and `head` is the
/// greatest sequence assigned so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayStreamState {
    pub epoch: [u8; 32],
    pub head: u64,
    pub floor: u64,
}

/// One signed operation at its relay-local insertion sequence.
#[derive(Clone, Debug)]
pub struct RelayLogEntry {
    pub seq: u64,
    pub op: SignedOp,
}

/// An atomic view of a relay stream and a bounded page from it.
#[derive(Clone, Debug)]
pub struct RelayLogPage {
    pub state: RelayStreamState,
    pub entries: Vec<RelayLogEntry>,
}

/// An append-only, totally-ordered set of signed ops, keyed by the full
/// `(hlc, device, op_id)` order key so two distinct ops never overwrite each
/// other.
pub struct OpLog {
    ops: BTreeMap<OrderKey, SignedOp>,
    ids: HashSet<OpId>,
    relay_epoch: [u8; 32],
    relay_order: Vec<OrderKey>,
}

impl Default for OpLog {
    fn default() -> Self {
        let mut relay_epoch = [0u8; 32];
        OsRng.fill_bytes(&mut relay_epoch);
        if relay_epoch == [0u8; 32] {
            relay_epoch[0] = 1;
        }
        Self {
            ops: BTreeMap::new(),
            ids: HashSet::new(),
            relay_epoch,
            relay_order: Vec::new(),
        }
    }
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
        let order_key = op.order_key();
        self.relay_order.push(order_key);
        self.ops.insert(order_key, op);
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

    /// Current relay-local stream identity and insertion bounds.
    pub fn relay_state(&self) -> RelayStreamState {
        RelayStreamState {
            epoch: self.relay_epoch,
            head: self.relay_order.len() as u64,
            floor: 0,
        }
    }

    /// Operations strictly after `after`, ordered by first local insertion,
    /// independent of their semantic [`OrderKey`].
    pub fn relay_page(&self, after: u64, limit: usize) -> RelayLogPage {
        let start = usize::try_from(after)
            .unwrap_or(usize::MAX)
            .min(self.relay_order.len());
        let entries = self
            .relay_order
            .iter()
            .enumerate()
            .skip(start)
            .take(limit)
            .map(|(index, order_key)| RelayLogEntry {
                seq: index as u64 + 1,
                op: self
                    .ops
                    .get(order_key)
                    .expect("relay order references an inserted op")
                    .clone(),
            })
            .collect();
        RelayLogPage {
            state: self.relay_state(),
            entries,
        }
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

    /// Relay-local stream state, when this source supports the v2 insertion-
    /// ordered transport. The default keeps existing implementations and v1
    /// routes working unchanged.
    fn relay_state(&self) -> Result<Option<RelayStreamState>, String> {
        Ok(None)
    }

    /// Atomic relay stream state plus operations strictly after `after`, capped
    /// at `limit`. `Ok(None)` means the source supports only v1.
    fn relay_page(&self, _after: u64, _limit: usize) -> Result<Option<RelayLogPage>, String> {
        Ok(None)
    }
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

    fn relay_state(&self) -> Result<Option<RelayStreamState>, String> {
        Ok(Some(
            self.lock().expect("oplog mutex poisoned").relay_state(),
        ))
    }

    fn relay_page(&self, after: u64, limit: usize) -> Result<Option<RelayLogPage>, String> {
        Ok(Some(
            self.lock()
                .expect("oplog mutex poisoned")
                .relay_page(after, limit),
        ))
    }
}
