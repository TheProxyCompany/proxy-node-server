//! Hybrid logical clock, backed by [`uhlc`]. A reading is a single NTP64 `u64`:
//! the upper 32 bits are Unix seconds, the lower 32 bits a fraction, with the
//! lowest bits reserved as an intra-instant counter. Numeric `Ord` over that
//! `u64` is exactly HLC happens-before order, so a reading collapses into one
//! scalar while keeping the total order [`OrderKey`](crate::op::OrderKey)
//! depends on intact.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::HlcError;
use crate::identity::DeviceId;

/// Maximum tolerated forward drift of a remote reading relative to local
/// physical time (1 hour). A remote timestamp further ahead is rejected by
/// [`NodeClock::update`] rather than folded in, so one peer with a broken clock
/// cannot drag the whole mesh's timeline forward. uhlc's own default (500ms) is
/// too tight for laptops that sleep.
pub const DEFAULT_MAX_DELTA: Duration = Duration::from_secs(3_600);

/// A uhlc NTP64 reading. Numeric `Ord` over the inner `u64` is HLC
/// happens-before order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc(pub u64);

impl Hlc {
    pub const ZERO: Hlc = Hlc(0);
}

/// Generates monotonic HLC readings for one device. Uses interior mutability, so
/// every method takes `&self`.
pub struct NodeClock {
    hlc: uhlc::HLC,
}

impl NodeClock {
    /// Build a clock bound to this device's id, with the drift guard set to
    /// [`DEFAULT_MAX_DELTA`].
    pub fn new(device: &DeviceId) -> Self {
        Self::with_max_delta(device, DEFAULT_MAX_DELTA)
    }

    pub fn with_max_delta(device: &DeviceId, max_delta: Duration) -> Self {
        let hlc = uhlc::HLCBuilder::default()
            .with_id(clock_id(device))
            .with_max_delta(max_delta)
            .build();
        Self { hlc }
    }

    /// Timestamp a locally originated op.
    pub fn now(&self) -> Hlc {
        Hlc(self.hlc.new_timestamp().get_time().as_u64())
    }

    /// Fold a remote reading (stamped by `from`) into local state and return a
    /// reading strictly greater than both. Rejects a remote more than the
    /// configured max delta ahead of local physical time.
    pub fn update(&self, remote: Hlc, from: &DeviceId) -> Result<Hlc, HlcError> {
        let ts = uhlc::Timestamp::new(uhlc::NTP64(remote.0), clock_id(from));
        self.hlc
            .update_with_timestamp(&ts)
            .map_err(HlcError::RemoteDrift)?;
        Ok(self.now())
    }
}

/// Derive a uhlc clock id from the first 16 bytes of the device id. `DeviceId`
/// is `sha256(SEC1 pubkey)`, so the leading 16 bytes are effectively never all
/// zero; the fallback keeps the function total for the degenerate case, since
/// `uhlc::ID` must be non-zero.
fn clock_id(device: &DeviceId) -> uhlc::ID {
    uhlc::ID::try_from(&device.as_bytes()[..16])
        .unwrap_or_else(|_| uhlc::ID::try_from([1u8]).expect("one non-zero byte is a valid id"))
}
