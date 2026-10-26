//! Push wake-up (`/watch`): a head-change notifier that turns the sleep between
//! pull rounds into a blocking wait resolving the instant the peer's head moves.

use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::log::{LogSource, RelayStreamState};
use crate::op::OrderKey;

/// Publisher side of the push wake-up, fed the new head from every op-append
/// path (local emit + remote pull-apply). Backed by a `tokio::sync::watch` used
/// as a pure tick: its value is advisory — `/watch` correctness reads the
/// authoritative [`LogSource::head`], never the channel value.
pub struct HeadPublisher {
    tx: watch::Sender<(u64, OrderKey)>,
}

impl HeadPublisher {
    pub fn new(initial: OrderKey) -> Self {
        let (tx, _rx) = watch::channel((0, initial));
        Self { tx }
    }

    /// A reader parked handlers block on. Cloneable through [`super::ServeState`].
    pub fn watch(&self) -> HeadWatch {
        HeadWatch {
            rx: Some(self.tx.subscribe()),
        }
    }

    /// Signal one newly inserted operation. Every call advances an internal
    /// arrival tick even when the semantic `OrderKey` head is unchanged, so v2
    /// watchers wake for a late lower-order op.
    pub fn publish(&self, head: OrderKey) {
        self.tx.send_modify(|current| {
            current.0 = current.0.wrapping_add(1);
            current.1 = head;
        });
    }
}

/// Reader side of the push wake-up, held in [`super::ServeState`].
#[derive(Clone)]
pub struct HeadWatch {
    rx: Option<watch::Receiver<(u64, OrderKey)>>,
}

impl HeadWatch {
    pub fn inert() -> Self {
        Self { rx: None }
    }

    /// Block until `log.head() > known` or `wait` elapses, then return the head
    /// to report.
    pub async fn until_head_changes<L: LogSource>(
        mut self,
        log: &L,
        known: OrderKey,
        wait: Duration,
    ) -> OrderKey {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(rx) = self.rx.as_mut() {
                rx.borrow_and_update();
            }
            let cur = log.head().unwrap_or(OrderKey::MIN);
            if cur > known {
                return cur;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return cur;
            }
            match self.rx.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        changed = rx.changed() => {
                            if changed.is_err() {
                                tokio::time::sleep(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await;
                                return log.head().unwrap_or(OrderKey::MIN);
                            }
                        }
                        _ = tokio::time::sleep(remaining) => {
                            return log.head().unwrap_or(OrderKey::MIN);
                        }
                    }
                }
                None => {
                    tokio::time::sleep(remaining).await;
                    return log.head().unwrap_or(OrderKey::MIN);
                }
            }
        }
    }

    /// Block until the relay-local stream changes relative to `(epoch, after)`
    /// or `wait` elapses.
    pub async fn until_relay_changes<L: LogSource>(
        mut self,
        log: &L,
        epoch: [u8; 32],
        after: u64,
        wait: Duration,
    ) -> Result<Option<RelayStreamState>, String> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(rx) = self.rx.as_mut() {
                rx.borrow_and_update();
            }
            let Some(state) = log.relay_state()? else {
                return Ok(None);
            };
            if state.epoch != epoch
                || after < state.floor
                || after > state.head
                || state.head > after
            {
                return Ok(Some(state));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(Some(state));
            }
            match self.rx.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        changed = rx.changed() => {
                            if changed.is_err() {
                                tokio::time::sleep(
                                    deadline.saturating_duration_since(Instant::now()),
                                )
                                .await;
                                return log.relay_state();
                            }
                        }
                        _ = tokio::time::sleep(remaining) => {
                            return log.relay_state();
                        }
                    }
                }
                None => {
                    tokio::time::sleep(remaining).await;
                    return log.relay_state();
                }
            }
        }
    }
}
