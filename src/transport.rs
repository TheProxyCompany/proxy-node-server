//! Phase-1 transport seam. Reserved: named and importable so the boundary
//! exists, but with no implementation. The async runtime (tokio) is added with
//! the pull loop, not here.

use crate::identity::DeviceId;
use crate::op::SignedOp;

/// A peer, addressed by its device id.
pub struct PeerId(pub DeviceId);

/// Where a peer resumes pulling from: the full `(hlc, device, op_id)` order key.
/// The log head doubles as the cursor; a first pull starts from
/// [`OrderKey::MIN`](crate::op::OrderKey::MIN).
pub type Cursor = crate::op::OrderKey;

/// Phase-1: incremental pull of a peer's op-log. Intentionally unimplemented.
/// Left synchronous here; the async runtime is added with the pull loop.
pub trait PullSource {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Return the peer's ops strictly after `since`, in HLC order.
    fn pull(&self, since: Cursor) -> Result<Vec<SignedOp>, Self::Error>;
}
