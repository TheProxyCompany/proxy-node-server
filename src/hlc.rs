//! Hybrid logical clock. A reading is physical microseconds since the Unix
//! epoch plus a logical counter; derived `Ord` is lexicographic `(wall,
//! counter)`, which is exactly HLC happens-before order.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::HlcError;

/// Maximum tolerated forward drift of a remote wall clock relative to local
/// physical time, in microseconds (1 hour). A remote timestamp further ahead
/// is rejected by [`HlcClock::update`] rather than folded in, so one peer with
/// a broken clock cannot drag the whole mesh's timeline forward.
pub const MAX_DRIFT_MICROS: u64 = 3_600_000_000;

/// A hybrid logical clock reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub wall: u64,
    pub counter: u32,
}

impl Hlc {
    pub const ZERO: Hlc = Hlc {
        wall: 0,
        counter: 0,
    };
}

/// Generates monotonic HLC readings. Not `Sync`; wrap in a mutex if shared.
pub struct HlcClock {
    last: Hlc,
    now_micros: fn() -> u64,
}

impl HlcClock {
    pub fn new() -> Self {
        Self::with_physical_clock(unix_micros)
    }

    pub fn with_physical_clock(now_micros: fn() -> u64) -> Self {
        Self {
            last: Hlc::ZERO,
            now_micros,
        }
    }

    /// Timestamp a locally originated op.
    pub fn now(&mut self) -> Hlc {
        let pt = (self.now_micros)();
        if pt > self.last.wall {
            self.last = Hlc {
                wall: pt,
                counter: 0,
            };
        } else {
            self.last = bump(self.last.wall, self.last.counter.checked_add(1));
        }
        self.last
    }

    /// Fold a received remote timestamp in, then return a reading strictly
    /// greater than both the local state and `remote`. Rejects a remote wall
    /// clock more than [`MAX_DRIFT_MICROS`] ahead of local physical time; that
    /// guard is also what keeps the strictly-greater contract honest, since an
    /// accepted remote can never sit at the top of the `u64` range.
    pub fn update(&mut self, remote: Hlc) -> Result<Hlc, HlcError> {
        let pt = (self.now_micros)();
        // checked_add: if the local physical clock sits within the drift bound
        // of u64::MAX, no remote can be proven sane — reject rather than let a
        // saturated bound admit wall values bump() cannot exceed.
        let bound = pt.checked_add(MAX_DRIFT_MICROS);
        if bound.is_none_or(|b| remote.wall > b) {
            return Err(HlcError::RemoteDrift {
                remote_wall: remote.wall,
                local_wall: pt,
            });
        }
        let w = self.last.wall.max(remote.wall).max(pt);
        let counter = if w == self.last.wall && w == remote.wall {
            self.last.counter.max(remote.counter).checked_add(1)
        } else if w == self.last.wall {
            self.last.counter.checked_add(1)
        } else if w == remote.wall {
            remote.counter.checked_add(1)
        } else {
            Some(0)
        };
        // Post-condition, checked rather than derived from bound arithmetic:
        // the reading must be strictly greater than both inputs. Only a clock
        // pinned at the end of representable time can fail this.
        let candidate = bump(w, counter);
        if candidate <= remote || candidate <= self.last {
            return Err(HlcError::Saturated);
        }
        self.last = candidate;
        Ok(candidate)
    }

    pub fn peek(&self) -> Hlc {
        self.last
    }

    #[cfg(test)]
    fn force_last(&mut self, last: Hlc) {
        self.last = last;
    }
}

/// Assemble the next reading. `counter` is `None` when the logical counter
/// saturated `u32::MAX`: rather than panic (debug) or wrap (release), advance
/// the wall clock by one microsecond and restart the counter, which keeps the
/// clock strictly monotonic.
fn bump(wall: u64, counter: Option<u32>) -> Hlc {
    match counter {
        Some(counter) => Hlc { wall, counter },
        None => match wall.checked_add(1) {
            Some(wall) => Hlc { wall, counter: 0 },
            // Pinned at the end of representable time: never goes backwards,
            // and `update`'s post-condition turns it into an error.
            None => Hlc {
                wall: u64::MAX,
                counter: u32::MAX,
            },
        },
    }
}

impl Default for HlcClock {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Thread-local so parallel tests each drive their own physical clock without
    // racing on shared state.
    thread_local! {
        static FROZEN: Cell<u64> = const { Cell::new(1_000) };
    }
    fn set_now(v: u64) {
        FROZEN.with(|c| c.set(v));
    }
    fn frozen_clock() -> u64 {
        FROZEN.with(|c| c.get())
    }

    #[test]
    fn ord_is_wall_then_counter() {
        assert!(
            Hlc {
                wall: 1,
                counter: 5
            } < Hlc {
                wall: 2,
                counter: 0
            }
        );
        assert!(
            Hlc {
                wall: 2,
                counter: 0
            } < Hlc {
                wall: 2,
                counter: 1
            }
        );
    }

    #[test]
    fn now_is_strictly_monotonic_under_frozen_physical_time() {
        set_now(1_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        let mut prev = clock.now();
        for _ in 0..1000 {
            let next = clock.now();
            assert!(next > prev, "{next:?} !> {prev:?}");
            prev = next;
        }
    }

    #[test]
    fn now_tracks_advancing_physical_time() {
        set_now(5_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        let a = clock.now();
        assert_eq!(
            a,
            Hlc {
                wall: 5_000,
                counter: 0
            }
        );
        let b = clock.now();
        assert_eq!(
            b,
            Hlc {
                wall: 5_000,
                counter: 1
            }
        );
        set_now(9_000);
        let c = clock.now();
        assert_eq!(
            c,
            Hlc {
                wall: 9_000,
                counter: 0
            }
        );
    }

    #[test]
    fn update_dominates_remote_and_local() {
        set_now(1_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        let local = clock.now();
        let remote = Hlc {
            wall: local.wall + 10_000,
            counter: 3,
        };
        let folded = clock.update(remote).unwrap();
        assert!(folded > remote);
        assert!(folded > local);
        assert_eq!(folded.wall, remote.wall);
        assert_eq!(folded.counter, 4);
    }

    #[test]
    fn update_rejects_remote_beyond_drift_bound() {
        set_now(1_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        let absurd = Hlc {
            wall: 1_000 + MAX_DRIFT_MICROS + 1,
            counter: 0,
        };
        assert!(clock.update(absurd).is_err());
        // The rejected remote must not have disturbed local state.
        assert_eq!(clock.peek(), Hlc::ZERO);
        // The end of the u64 range is unreachable through update: it is always
        // beyond the drift bound of any real physical clock.
        let end_of_time = Hlc {
            wall: u64::MAX,
            counter: u32::MAX,
        };
        assert!(clock.update(end_of_time).is_err());
    }

    // Regression, codex round 4: at pt == u64::MAX - MAX_DRIFT_MICROS the drift
    // bound admits wall == u64::MAX, where no strictly-greater reading exists.
    // The post-condition must reject it without disturbing local state.
    #[test]
    fn update_rejects_end_of_time_within_drift_bound() {
        set_now(u64::MAX - MAX_DRIFT_MICROS);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        let remote = Hlc {
            wall: u64::MAX,
            counter: u32::MAX,
        };
        assert!(matches!(clock.update(remote), Err(HlcError::Saturated)));
        assert_eq!(clock.peek(), Hlc::ZERO);
    }

    // Regression, finding 9: at counter == u32::MAX the next reading must bump
    // the wall by 1µs and reset the counter instead of overflowing.
    #[test]
    fn now_handles_counter_saturation_without_overflow() {
        set_now(1_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        clock.force_last(Hlc {
            wall: 1_000,
            counter: u32::MAX,
        });
        let next = clock.now();
        assert_eq!(
            next,
            Hlc {
                wall: 1_001,
                counter: 0
            }
        );
        assert!(
            next > Hlc {
                wall: 1_000,
                counter: u32::MAX
            }
        );
    }

    #[test]
    fn update_handles_counter_saturation_without_overflow() {
        set_now(1_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        clock.force_last(Hlc {
            wall: 2_000,
            counter: u32::MAX,
        });
        // remote ties the local wall at a saturated counter, forcing the bump.
        let folded = clock
            .update(Hlc {
                wall: 2_000,
                counter: u32::MAX,
            })
            .unwrap();
        assert_eq!(
            folded,
            Hlc {
                wall: 2_001,
                counter: 0
            }
        );
    }

    #[test]
    fn update_breaks_ties_on_counter() {
        set_now(7_000);
        let mut clock = HlcClock::with_physical_clock(frozen_clock);
        let local = clock.now(); // {7000, 0}
        let remote = Hlc {
            wall: local.wall,
            counter: 4,
        };
        let folded = clock.update(remote).unwrap();
        assert_eq!(folded.wall, 7_000);
        assert_eq!(folded.counter, 5);
    }
}
