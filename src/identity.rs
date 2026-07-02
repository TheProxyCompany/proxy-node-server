//! Device identity: a P-256 (secp256r1) signing key plus its derived, stable
//! device id. The device id is `sha256(compressed SEC1 public key)`, which is
//! deterministic across macOS, Linux, and Windows because it depends only on
//! the key bytes.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::IdentityError;

/// Stable per-install device identifier: SHA-256 of the compressed SEC1 public
/// key. Displays as lowercase hex; this is the value carried in
/// `X-Proxy-Device-ID`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, IdentityError> {
        let bytes = from_hex(s)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Reconstruct a device id from its 32 raw bytes, e.g. a persisted cursor
    /// or a wire envelope.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl core::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceId({})", self.to_hex())
    }
}

/// A P-256 (secp256r1) signing identity for one device.
pub struct DeviceIdentity {
    signing: SigningKey,
    verifying: VerifyingKey,
    device_id: DeviceId,
}

impl DeviceIdentity {
    /// Mint a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let signing = SigningKey::random(&mut OsRng);
        Self::from_signing(signing)
    }

    /// Import an existing raw 32-byte big-endian scalar. This is Swift
    /// `P256.Signing.PrivateKey.rawRepresentation`, exactly as Grand Central
    /// reads it from the macOS Keychain. No re-pairing.
    pub fn import_raw(scalar: &[u8; 32]) -> Result<Self, IdentityError> {
        let signing = SigningKey::from_slice(scalar).map_err(|_| IdentityError::InvalidScalar)?;
        Ok(Self::from_signing(signing))
    }

    /// Export the raw scalar for persistence, zeroized on drop.
    pub fn export_raw(&self) -> Zeroizing<[u8; 32]> {
        let field = self.signing.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&field);
        Zeroizing::new(out)
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Compressed SEC1 public key (33 bytes) — what peers store to verify this
    /// device.
    pub fn public_key_sec1(&self) -> [u8; 33] {
        sec1_compressed(&self.verifying)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// ECDSA/SHA-256 signature over `msg` (fixed 64-byte r‖s).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// Verify a signature against a device's public key. Associated, not
    /// `&self`: peers verify ops from devices whose private key they do not
    /// hold.
    pub fn verify(pubkey: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), IdentityError> {
        pubkey
            .verify(msg, sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Reconstruct a `DeviceId` from a peer's advertised compressed SEC1 key.
    pub fn device_id_from_sec1(sec1: &[u8; 33]) -> Result<DeviceId, IdentityError> {
        let verifying =
            VerifyingKey::from_sec1_bytes(sec1).map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(device_id_of(&verifying))
    }

    /// Derive the `DeviceId` a verifying key would carry. Used to check that a
    /// supplied key actually matches an op's claimed `device`.
    pub fn device_id_of_key(pubkey: &VerifyingKey) -> DeviceId {
        device_id_of(pubkey)
    }

    fn from_signing(signing: SigningKey) -> Self {
        let verifying = *signing.verifying_key();
        let device_id = device_id_of(&verifying);
        Self {
            signing,
            verifying,
            device_id,
        }
    }
}

fn sec1_compressed(key: &VerifyingKey) -> [u8; 33] {
    let point = key.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

fn device_id_of(key: &VerifyingKey) -> DeviceId {
    let sec1 = sec1_compressed(key);
    let digest = Sha256::digest(sec1);
    DeviceId(digest.into())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>, IdentityError> {
    if s.len() % 2 != 0 {
        return Err(IdentityError::InvalidHex);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, IdentityError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(IdentityError::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let id = DeviceIdentity::generate();
        let msg = b"replicate me";
        let sig = id.sign(msg);
        assert!(DeviceIdentity::verify(id.verifying_key(), msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"original");
        assert!(DeviceIdentity::verify(id.verifying_key(), b"tampered", &sig).is_err());
    }

    #[test]
    fn import_is_deterministic() {
        let original = DeviceIdentity::generate();
        let raw = original.export_raw();

        let a = DeviceIdentity::import_raw(&raw).unwrap();
        let b = DeviceIdentity::import_raw(&raw).unwrap();

        // Same key bytes -> same device id, every time, on every platform.
        assert_eq!(original.device_id(), a.device_id());
        assert_eq!(a.device_id(), b.device_id());
        assert_eq!(a.public_key_sec1(), b.public_key_sec1());
    }

    #[test]
    fn device_id_matches_sec1_derivation() {
        let id = DeviceIdentity::generate();
        let from_sec1 = DeviceIdentity::device_id_from_sec1(&id.public_key_sec1()).unwrap();
        assert_eq!(id.device_id(), from_sec1);
    }

    #[test]
    fn device_id_hex_round_trips() {
        let id = DeviceIdentity::generate().device_id();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(DeviceId::from_hex(&hex).unwrap(), id);
    }

    #[test]
    fn from_hex_rejects_junk() {
        assert!(DeviceId::from_hex("zz").is_err());
        assert!(DeviceId::from_hex("abc").is_err());
    }

    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = from_hex(hex).unwrap();
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    // Cross-language compatibility with Apple CryptoKit. The vector below was
    // produced on macOS by scripts/gen_cryptokit_fixture.swift using
    // P256.Signing.PrivateKey (rawRepresentation, compressed SEC1 public key,
    // and an ECDSA/SHA-256 signature over a fixed message). Importing the raw
    // scalar in Rust must reproduce CryptoKit's SEC1 key and DeviceId, and the
    // CryptoKit signature must verify.
    #[test]
    fn cryptokit_cross_language_vector() {
        const MESSAGE: &[u8] = b"proxy-node-server cross-language fixture";
        let private_raw: [u8; 32] =
            decode("c00996f52071c57f7d6d3d996acd3008480b0639e524db732f36f43cb9da5cbb");
        let public_sec1: [u8; 33] =
            decode("0367718916eb67bedad789d35b2159b9f4a7ba93dc929e39ff035bdca223f64482");
        let signature: [u8; 64] = decode(
            "94c65022727aedc0ca61a6648a00417118bda661d0dde0dbb7d2aab236f12da6\
             032bd9687bb1fdce8ef8b0966cd2c156fb82b7aa7e2383553e31b92d874a2c00",
        );

        let identity = DeviceIdentity::import_raw(&private_raw).unwrap();

        // Same private scalar -> byte-identical compressed SEC1 public key.
        assert_eq!(identity.public_key_sec1(), public_sec1);

        // DeviceId derives from that SEC1 key identically on both sides.
        let from_sec1 = DeviceIdentity::device_id_from_sec1(&public_sec1).unwrap();
        assert_eq!(identity.device_id(), from_sec1);

        // The CryptoKit signature verifies under the imported key.
        let sig = Signature::from_slice(&signature).unwrap();
        assert!(DeviceIdentity::verify(identity.verifying_key(), MESSAGE, &sig).is_ok());
    }
}
