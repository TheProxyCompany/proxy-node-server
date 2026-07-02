//! Transport seam. [`PeerId`] and [`Cursor`] are always available; the
//! [`PullSource`] trait and its HTTP implementation ([`crate::net`]) live behind
//! the `pull-http` feature, which pulls in the async runtime.

use crate::identity::DeviceId;

/// A peer, addressed by its device id.
pub struct PeerId(pub DeviceId);

/// Where a peer resumes pulling from: the full `(hlc, device, op_id)` order key.
/// The log head doubles as the cursor; a first pull starts from
/// [`OrderKey::MIN`](crate::op::OrderKey::MIN).
pub type Cursor = crate::op::OrderKey;

/// Incremental pull of a peer's op-log. Async because the only implementor
/// ([`crate::net::HttpPullSource`]) is network-backed.
#[cfg(feature = "pull-http")]
#[allow(async_fn_in_trait)] // callers are the single-threaded pull loop; no Send bound is needed
pub trait PullSource {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Return the peer's ops strictly after `since`, in HLC order.
    async fn pull(&self, since: Cursor) -> Result<Vec<crate::op::SignedOp>, Self::Error>;
}
