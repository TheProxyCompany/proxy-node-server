//! Crate-wide error enums. No panics on the trusted path.

use thiserror::Error;

/// Failures folding remote timestamps into the local hybrid logical clock.
#[derive(Debug, Error)]
pub enum HlcError {
    /// The remote reading is further ahead of local physical time than the
    /// configured drift bound. Wraps uhlc's rejection message.
    #[error("remote clock rejected by drift guard: {0}")]
    RemoteDrift(String),
}

/// Failures in device-identity handling: key import, hex decoding, verification.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid hex string")]
    InvalidHex,

    #[error("expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("invalid P-256 private scalar")]
    InvalidScalar,

    #[error("invalid P-256 public key encoding")]
    InvalidPublicKey,

    #[error("signature verification failed")]
    BadSignature,
}

/// Failures in sealing, verifying, or (de)serializing a signed op envelope.
#[derive(Debug, Error)]
pub enum OpError {
    #[error(transparent)]
    Identity(#[from] IdentityError),

    #[error("canonical encoding error: {0}")]
    Encoding(#[from] postcard::Error),

    #[error("op id does not match content")]
    IdMismatch,

    #[error("supplied public key does not derive the op's device id")]
    DeviceMismatch,

    #[error("signature is not in low-S canonical form")]
    MalleableSignature,

    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid store id: must be 1..=64 ASCII bytes")]
    InvalidStoreId,

    #[error("malformed envelope field length")]
    BadLength,
}

/// Failure while replaying a log into a [`crate::store::Store`].
#[derive(Debug, Error)]
pub enum ReplayError<E: std::error::Error + Send + Sync + 'static> {
    #[error("store error during replay: {0}")]
    Store(#[source] E),
}

/// Failures reading or writing the append-only op-log durability file.
#[derive(Debug, Error)]
pub enum DurabilityError {
    #[error("op-log file io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Op(#[from] OpError),

    #[error("op-log writer poisoned: a torn frame could not be rolled back")]
    Poisoned,
}

/// Failures in the HTTP pull transport.
#[cfg(feature = "pull-http")]
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("http request failed: {0}")]
    Http(String),

    #[error("malformed wire payload: {0}")]
    Wire(String),

    #[error("replay failed during sync: {0}")]
    Replay(String),

    /// A pulled op could not be verified (unknown device or a bad signature).
    /// The batch is aborted and the cursor is not advanced past this op, so a
    /// forged high-order-key op cannot poison the cursor and skip later ops.
    #[error("op from device {device} failed verification: {reason}")]
    Verify { device: String, reason: String },

    /// A pulled op's HLC is further ahead of local physical time than the drift
    /// guard allows. The op is rejected before it enters the log; the batch is
    /// aborted and the cursor is not advanced past it.
    #[error("op from device {device} rejected by drift guard (hlc {hlc}): {reason}")]
    Drift {
        device: String,
        hlc: u64,
        reason: String,
    },

    #[error(transparent)]
    Op(#[from] OpError),

    #[error(transparent)]
    Identity(#[from] IdentityError),

    #[error(transparent)]
    Durability(#[from] DurabilityError),

    #[error("peer advertised device {advertised} but its key derives {derived}")]
    IdentityMismatch { advertised: String, derived: String },
}
