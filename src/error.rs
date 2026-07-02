//! Crate-wide error enums. No panics on the trusted path.

use thiserror::Error;

/// Failures folding remote timestamps into the local hybrid logical clock.
#[derive(Debug, Error)]
pub enum HlcError {
    #[error(
        "remote wall clock {remote_wall}µs exceeds local {local_wall}µs by more than the drift bound"
    )]
    RemoteDrift { remote_wall: u64, local_wall: u64 },

    #[error("hybrid logical clock is saturated at the end of representable time")]
    Saturated,
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
