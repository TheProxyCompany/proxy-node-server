//! The signed replication envelope: a versioned, canonically-encoded op body,
//! its low-S P-256 signature, and a content-address over the body.

use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::OpError;
use crate::hlc::Hlc;
use crate::identity::{DeviceId, DeviceIdentity};

/// Current op envelope version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Domain-separation prefix mixed into every op signature. A signature over an
/// op can never be replayed as a signature in any other protocol context (and
/// vice versa), independent of what the payload bytes happen to look like.
pub const SIGNING_CONTEXT: &[u8] = b"proxy-node-server/op/v1\0";

/// Maximum length of a store namespace, in bytes.
pub const MAX_STORE_ID_LEN: usize = 64;

/// Namespaces one Store within a shared op-log (e.g. "kv", "proxydb",
/// "trellis"). Owns its string so a decoded wire value never has to be leaked;
/// validated to be non-empty ASCII no longer than [`MAX_STORE_ID_LEN`] bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoreId(String);

impl StoreId {
    /// Build a validated store id. Rejects empty, non-ASCII, or over-long
    /// namespaces before allocating, so a hostile peer cannot force even a
    /// transient oversized allocation; the owned value is built from the
    /// validated slice itself.
    pub fn new(s: impl AsRef<str>) -> Result<Self, OpError> {
        let r = s.as_ref();
        if r.is_empty() || r.len() > MAX_STORE_ID_LEN || !r.is_ascii() {
            return Err(OpError::InvalidStoreId);
        }
        Ok(Self(r.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Content address of a sealed op: SHA-256 over the canonical body only. The
/// signature is deliberately excluded so ECDSA malleability cannot mint
/// multiple ids for one semantic op.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpId([u8; 32]);

impl OpId {
    /// Reconstruct an op id from its 32 raw bytes, e.g. a persisted cursor.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl core::fmt::Debug for OpId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OpId({})", self.to_hex())
    }
}

/// Global total-order key for replay and cursors. Compared lexicographically as
/// `(hlc, device, op_id)`, so every peer sorts an identical set of ops
/// identically and no two distinct ops can ever collide on the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrderKey {
    pub hlc: Hlc,
    pub device: DeviceId,
    pub op_id: OpId,
}

impl OrderKey {
    /// The smallest possible key: the initial cursor for a first pull.
    pub const MIN: OrderKey = OrderKey {
        hlc: Hlc::ZERO,
        device: DeviceId::from_bytes([0; 32]),
        op_id: OpId::from_bytes([0; 32]),
    };

    /// Fixed 72-byte wire form: big-endian `Hlc` ‖ device ‖ op id. Big-endian so
    /// lexicographic byte order matches the numeric `(hlc, device, op_id)` order.
    /// Shared by the persisted cursor, the `since` query param, and the pull
    /// response's `next` field.
    pub fn to_wire(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[..8].copy_from_slice(&self.hlc.0.to_be_bytes());
        out[8..40].copy_from_slice(self.device.as_bytes());
        out[40..].copy_from_slice(self.op_id.as_bytes());
        out
    }

    pub fn from_wire(bytes: &[u8; 72]) -> Self {
        let mut hlc = [0u8; 8];
        hlc.copy_from_slice(&bytes[..8]);
        let mut device = [0u8; 32];
        device.copy_from_slice(&bytes[8..40]);
        let mut op_id = [0u8; 32];
        op_id.copy_from_slice(&bytes[40..]);
        OrderKey {
            hlc: Hlc(u64::from_be_bytes(hlc)),
            device: DeviceId::from_bytes(device),
            op_id: OpId::from_bytes(op_id),
        }
    }
}

/// The signed portion of an op. Serialized with a versioned canonical
/// (deterministic postcard) encoding so the signature is reproducible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpBody {
    pub v: u8,
    pub hlc: Hlc,
    pub device: DeviceId,
    pub store: StoreId,
    pub payload: Vec<u8>,
}

/// The unit of replication: a signed, content-addressed op.
#[derive(Clone, Debug)]
pub struct SignedOp {
    pub body: OpBody,
    pub sig: [u8; 64],
    pub id: OpId,
}

impl SignedOp {
    /// Stamp `body.device` with `identity`'s device id, canonically encode the
    /// body, sign it under [`SIGNING_CONTEXT`] (normalized to low-S), and
    /// content-address the body.
    pub fn seal(mut body: OpBody, identity: &DeviceIdentity) -> Result<Self, OpError> {
        body.device = identity.device_id();
        let canon = canonical_body(&body)?;
        let sig = identity.sign(&signing_input(&canon));
        // RFC 6979 already yields low-S here, but normalize defensively so a
        // sealed op is never rejected by its own malleability check on verify.
        let sig = sig.normalize_s().unwrap_or(sig);
        let sig_bytes = signature_bytes(&sig);
        let id = content_id(&canon);
        Ok(Self {
            body,
            sig: sig_bytes,
            id,
        })
    }

    /// Verify that `id` matches the canonical body, that `pubkey` derives
    /// `body.device`, and that the low-S signature is valid. Caller supplies the
    /// key resolved from `body.device` via the device registry.
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<(), OpError> {
        let canon = canonical_body(&self.body)?;
        if content_id(&canon) != self.id {
            return Err(OpError::IdMismatch);
        }
        if DeviceIdentity::device_id_of_key(pubkey) != self.body.device {
            return Err(OpError::DeviceMismatch);
        }
        let sig = Signature::from_slice(&self.sig).map_err(|_| OpError::BadLength)?;
        if sig.normalize_s().is_some() {
            return Err(OpError::MalleableSignature);
        }
        DeviceIdentity::verify(pubkey, &signing_input(&canon), &sig)?;
        Ok(())
    }

    /// Global total-order key for replay and cursors: `(hlc, device, op_id)`.
    pub fn order_key(&self) -> OrderKey {
        OrderKey {
            hlc: self.body.hlc,
            device: self.body.device,
            op_id: self.id,
        }
    }

    /// Canonical bytes of the whole envelope for wire/disk.
    pub fn to_bytes(&self) -> Result<Vec<u8>, OpError> {
        let repr = EnvelopeRepr {
            body: body_repr(&self.body),
            sig: &self.sig,
            id: self.id.as_bytes(),
        };
        Ok(postcard::to_allocvec(&repr)?)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, OpError> {
        let repr: EnvelopeRepr = postcard::from_bytes(buf)?;
        if repr.body.v != ENVELOPE_VERSION {
            return Err(OpError::UnsupportedVersion(repr.body.v));
        }
        if repr.sig.len() != 64 || repr.id.len() != 32 {
            return Err(OpError::BadLength);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(repr.sig);
        let mut id = [0u8; 32];
        id.copy_from_slice(repr.id);
        let body = OpBody {
            v: repr.body.v,
            hlc: repr.body.hlc,
            device: DeviceId::from_bytes(repr.body.device),
            store: StoreId::new(repr.body.store)?,
            payload: repr.body.payload.to_vec(),
        };
        Ok(Self {
            body,
            sig,
            id: OpId(id),
        })
    }
}

/// Borrowed, serde-friendly mirror of `OpBody` for canonical encoding.
/// `StoreId(&'static str)` and `DeviceId([u8; 32])` are flattened here so the
/// derive stays inside serde's supported shapes.
#[derive(Serialize, Deserialize)]
struct BodyRepr<'a> {
    v: u8,
    hlc: Hlc,
    device: [u8; 32],
    #[serde(borrow)]
    store: &'a str,
    payload: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct EnvelopeRepr<'a> {
    #[serde(borrow)]
    body: BodyRepr<'a>,
    sig: &'a [u8],
    id: &'a [u8],
}

fn body_repr(body: &OpBody) -> BodyRepr<'_> {
    BodyRepr {
        v: body.v,
        hlc: body.hlc,
        device: *body.device.as_bytes(),
        store: body.store.as_str(),
        payload: &body.payload,
    }
}

fn canonical_body(body: &OpBody) -> Result<Vec<u8>, OpError> {
    Ok(postcard::to_allocvec(&body_repr(body))?)
}

/// The exact bytes an op signature covers: the domain-separation context
/// followed by the canonical body.
fn signing_input(canon: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNING_CONTEXT.len() + canon.len());
    input.extend_from_slice(SIGNING_CONTEXT);
    input.extend_from_slice(canon);
    input
}

fn content_id(canon: &[u8]) -> OpId {
    let mut hasher = Sha256::new();
    hasher.update(canon);
    OpId(hasher.finalize().into())
}

fn signature_bytes(sig: &Signature) -> [u8; 64] {
    let ga = sig.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&ga);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;

    fn sample_body(identity: &DeviceIdentity) -> OpBody {
        OpBody {
            v: ENVELOPE_VERSION,
            hlc: Hlc(42),
            device: identity.device_id(),
            store: StoreId::new("kv").unwrap(),
            payload: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn seal_then_verify() {
        let id = DeviceIdentity::generate();
        let op = SignedOp::seal(sample_body(&id), &id).unwrap();
        assert!(op.verify(id.verifying_key()).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let id = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let op = SignedOp::seal(sample_body(&id), &id).unwrap();
        assert!(op.verify(other.verifying_key()).is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let id = DeviceIdentity::generate();
        let mut op = SignedOp::seal(sample_body(&id), &id).unwrap();
        op.body.payload[0] ^= 0xff;
        assert!(op.verify(id.verifying_key()).is_err());
    }

    // The signature must cover the domain-separation context, not the bare
    // canonical body — otherwise an op signature could double as a signature
    // in some other protocol that happens to sign the same bytes.
    #[test]
    fn signature_covers_domain_separation_context() {
        let id = DeviceIdentity::generate();
        let op = SignedOp::seal(sample_body(&id), &id).unwrap();
        let canon = canonical_body(&op.body).unwrap();
        let sig = Signature::from_slice(&op.sig).unwrap();
        assert!(DeviceIdentity::verify(id.verifying_key(), &canon, &sig).is_err());
        assert!(DeviceIdentity::verify(id.verifying_key(), &signing_input(&canon), &sig).is_ok());
    }

    #[test]
    fn envelope_bytes_round_trip() {
        let id = DeviceIdentity::generate();
        let op = SignedOp::seal(sample_body(&id), &id).unwrap();
        let bytes = op.to_bytes().unwrap();
        let back = SignedOp::from_bytes(&bytes).unwrap();
        assert_eq!(back.body, op.body);
        assert_eq!(back.sig, op.sig);
        assert_eq!(back.id, op.id);
        // Survives a decode round-trip and still verifies.
        assert!(back.verify(id.verifying_key()).is_ok());
    }

    #[test]
    fn seal_is_deterministic() {
        let id = DeviceIdentity::generate();
        let a = SignedOp::seal(sample_body(&id), &id).unwrap();
        let b = SignedOp::seal(sample_body(&id), &id).unwrap();
        // P-256 signatures are deterministic (RFC 6979), so the content id is too.
        assert_eq!(a.id, b.id);
        assert_eq!(a.sig, b.sig);
    }

    // Regression, finding 4: seal ignores whatever device the caller put on the
    // body and stamps the signer's own device id.
    #[test]
    fn seal_overwrites_device_with_signer() {
        let signer = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let mut body = sample_body(&signer);
        body.device = other.device_id();
        let op = SignedOp::seal(body, &signer).unwrap();
        assert_eq!(op.body.device, signer.device_id());
        assert!(op.verify(signer.verifying_key()).is_ok());
    }

    // Regression, finding 3: a key that does not derive body.device is rejected
    // even though it produced a valid signature over the same canonical body.
    #[test]
    fn verify_rejects_key_not_deriving_device() {
        let victim = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let mut op = SignedOp::seal(sample_body(&victim), &victim).unwrap();
        // Forge a valid attacker signature over the untouched body, but leave
        // body.device pointing at the victim.
        let canon = canonical_body(&op.body).unwrap();
        let forged = attacker.sign(&canon);
        let forged = forged.normalize_s().unwrap_or(forged);
        op.sig = signature_bytes(&forged);
        let err = op.verify(attacker.verifying_key()).unwrap_err();
        assert!(matches!(err, OpError::DeviceMismatch));
    }

    // Regression, finding 5: content id covers the body only, so the high-S
    // malleable twin of a signature keeps the same OpId and is rejected as
    // non-canonical rather than accepted as a distinct op.
    #[test]
    fn verify_rejects_high_s_signature() {
        use p256::elliptic_curve::ff::PrimeField;

        let id = DeviceIdentity::generate();
        let mut op = SignedOp::seal(sample_body(&id), &id).unwrap();
        let sig = Signature::from_slice(&op.sig).unwrap();
        let high_s = -*sig.s();
        let flipped = Signature::from_scalars(sig.r().to_repr(), high_s.to_repr()).unwrap();
        assert!(flipped.normalize_s().is_some(), "expected the high-S twin");
        op.sig = signature_bytes(&flipped);
        // OpId is unchanged because it never covered the signature.
        let canon = canonical_body(&op.body).unwrap();
        assert_eq!(content_id(&canon), op.id);
        let err = op.verify(id.verifying_key()).unwrap_err();
        assert!(matches!(err, OpError::MalleableSignature));
    }

    // Regression, finding 7: envelopes carrying an unknown version are rejected.
    #[test]
    fn from_bytes_rejects_unsupported_version() {
        let id = DeviceIdentity::generate();
        let mut body = sample_body(&id);
        body.v = ENVELOPE_VERSION + 1;
        let op = SignedOp::seal(body, &id).unwrap();
        let bytes = op.to_bytes().unwrap();
        let err = SignedOp::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, OpError::UnsupportedVersion(v) if v == ENVELOPE_VERSION + 1));
    }

    #[test]
    fn order_key_wire_round_trips() {
        let id = DeviceIdentity::generate();
        let op = SignedOp::seal(sample_body(&id), &id).unwrap();
        let key = op.order_key();
        assert_eq!(OrderKey::from_wire(&key.to_wire()), key);
        // MIN maps to all zeros and back.
        assert_eq!(OrderKey::MIN.to_wire(), [0u8; 72]);
        assert_eq!(OrderKey::from_wire(&[0u8; 72]), OrderKey::MIN);
    }

    // Big-endian encoding makes lexicographic byte order match the numeric
    // `(hlc, device, op_id)` order the log relies on.
    #[test]
    fn order_key_wire_preserves_order() {
        let lo = OrderKey {
            hlc: Hlc(10),
            device: DeviceId::from_bytes([0; 32]),
            op_id: OpId::from_bytes([0; 32]),
        };
        let hi = OrderKey {
            hlc: Hlc(11),
            device: DeviceId::from_bytes([0; 32]),
            op_id: OpId::from_bytes([0; 32]),
        };
        assert!(lo < hi);
        assert!(lo.to_wire() < hi.to_wire());
    }

    #[test]
    fn store_id_rejects_out_of_bounds() {
        assert!(StoreId::new("").is_err());
        assert!(StoreId::new("kv").is_ok());
        assert!(StoreId::new("a".repeat(MAX_STORE_ID_LEN)).is_ok());
        assert!(StoreId::new("a".repeat(MAX_STORE_ID_LEN + 1)).is_err());
        assert!(StoreId::new("caf\u{e9}").is_err());
    }
}
