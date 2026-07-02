//! Op-log engine: an append-only, HLC-ordered set of signed ops with dedup by
//! content id. The reference impl is in-memory; the shape lets Grand Central
//! back it with proxy.db.

use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;

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
    let store_id = store.store_id();
    for op in log.iter() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::identity::DeviceIdentity;
    use crate::op::{ENVELOPE_VERSION, OpBody, StoreId};

    fn op_with(id: &DeviceIdentity, wall: u64, counter: u32, payload: Vec<u8>) -> SignedOp {
        let body = OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc { wall, counter },
            device: id.device_id(),
            store: StoreId::new("kv").unwrap(),
            payload,
        };
        SignedOp::seal(body, id).unwrap()
    }

    fn op_at(id: &DeviceIdentity, wall: u64, counter: u32) -> SignedOp {
        op_with(id, wall, counter, vec![wall as u8, counter as u8])
    }

    #[test]
    fn append_dedups_by_id() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        let op = op_at(&id, 10, 0);
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
        let a = op_with(&id, 10, 0, vec![0xaa]);
        let b = op_with(&id, 10, 0, vec![0xbb]);
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
        log.append(op_at(&id, 30, 0));
        log.append(op_at(&id, 10, 0));
        log.append(op_at(&id, 20, 5));
        log.append(op_at(&id, 20, 1));

        let order: Vec<Hlc> = log.iter().map(|o| o.body.hlc).collect();
        assert_eq!(
            order,
            vec![
                Hlc {
                    wall: 10,
                    counter: 0
                },
                Hlc {
                    wall: 20,
                    counter: 1
                },
                Hlc {
                    wall: 20,
                    counter: 5
                },
                Hlc {
                    wall: 30,
                    counter: 0
                },
            ]
        );
    }

    #[test]
    fn since_and_head() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        assert_eq!(log.head(), None);
        let first = op_at(&id, 10, 0);
        log.append(first.clone());
        log.append(op_at(&id, 20, 0));
        log.append(op_at(&id, 30, 0));

        assert_eq!(log.head().map(|k| k.hlc.wall), Some(30));
        let after: Vec<u64> = log
            .since(first.order_key())
            .map(|o| o.body.hlc.wall)
            .collect();
        assert_eq!(after, vec![20, 30]);
    }

    // Regression, finding 2: a second op tying the cursor's HLC must not be
    // skipped. With an HLC-only cursor, `hlc > cursor` dropped every op sharing
    // the cursor's HLC; the full order key resumes strictly after just the one.
    #[test]
    fn since_does_not_skip_ops_tying_cursor_hlc() {
        let id = DeviceIdentity::generate();
        let mut log = OpLog::new();
        let a = op_with(&id, 10, 0, vec![0x01]);
        let b = op_with(&id, 10, 0, vec![0x02]);
        log.append(a.clone());
        log.append(b.clone());
        log.append(op_at(&id, 20, 0));

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
}
