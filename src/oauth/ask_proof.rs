//! Signed asks (`ask-proof:v1`) and party scopes (`party:<id>;...`) over `<name>.proxy.ing`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, VerifyingKey};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use super::Ask;
use crate::address::AgentAddress;
pub use crate::address::host_of_user;
use crate::identity::{DeviceIdentity, encode_hex};

pub const PROOF_PREFIX: &str = "ask-proof:";
const PROOF_VERSION: &str = "v1";
pub const PAYLOAD_VERSION: &str = "proxy.ing-ask-v1";
pub const KIND_SEAT: &str = "seat";
pub const ASK_LIFETIME_SECS: u64 = 10 * 60;
pub const CLOCK_SKEW_SECS: u64 = 60;
pub const NONCE_MEMORY_SECS: u64 = 24 * 60 * 60;
pub const UNSIGNED_ASKS_UNTIL: u64 = 1_793_491_200;
pub const PROXY_ING_API: &str = "https://api.theproxycompany.com";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyScope {
    pub conversation_id: String,
    pub title: String,
    pub host: String,
    pub agent: String,
    pub loadout: String,
}

impl PartyScope {
    pub const PREFIX: &'static str = "party:";

    pub fn to_scope(&self) -> String {
        format!(
            "{}{};title={};host={};agents={};loadout={}",
            Self::PREFIX,
            self.conversation_id,
            utf8_percent_encode(&self.title, NON_ALPHANUMERIC),
            self.host,
            self.agent,
            self.loadout
        )
    }

    pub fn parse(scope: &str) -> Option<Self> {
        let rest = scope
            .split_whitespace()
            .next()?
            .strip_prefix(Self::PREFIX)?;
        let mut parts = rest.split(';');
        let conversation_id = parts.next()?.trim().to_string();
        if conversation_id.is_empty() {
            return None;
        }
        let mut parsed = Self {
            conversation_id,
            title: String::new(),
            host: String::new(),
            agent: "proxy".to_string(),
            loadout: "default".to_string(),
        };
        for part in parts {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            match name.trim() {
                "title" => {
                    parsed.title = percent_decode_str(value)
                        .decode_utf8()
                        .map(|title| title.into_owned())
                        .unwrap_or_else(|_| value.to_string())
                }
                "host" => parsed.host = value.trim().to_string(),
                "agents" => parsed.agent = value.trim().to_string(),
                "loadout" => parsed.loadout = value.trim().to_string(),
                _ => {}
            }
        }
        if parsed.title.trim().is_empty() {
            parsed.title = "Untitled Party".to_string();
        }
        Some(parsed)
    }
}

pub fn party_scope_of(scope: Option<&str>) -> Option<PartyScope> {
    scope?.split_whitespace().find_map(PartyScope::parse)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AskProof {
    pub key_id: String,
    pub to: String,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: String,
}

impl AskProof {
    pub fn to_word(&self) -> String {
        format!(
            "{PROOF_PREFIX}{PROOF_VERSION};key={};to={};exp={};nonce={};sig={}",
            self.key_id, self.to, self.expires_at, self.nonce, self.signature
        )
    }

    pub fn parse(word: &str) -> Result<Self, String> {
        let rest = word
            .strip_prefix(PROOF_PREFIX)
            .ok_or_else(|| "not an ask proof".to_string())?;
        let mut parts = rest.split(';');
        if parts.next() != Some(PROOF_VERSION) {
            return Err("an ask proof of a version this Mac does not read".to_string());
        }
        let (mut key_id, mut to, mut expires_at, mut nonce, mut signature) =
            (None, None, None, None, None);
        for part in parts {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let slot = match name {
                "key" => &mut key_id,
                "to" => &mut to,
                "exp" => &mut expires_at,
                "nonce" => &mut nonce,
                "sig" => &mut signature,
                _ => continue,
            };
            if slot.is_some() {
                return Err(format!("the ask proof names {name} twice"));
            }
            *slot = Some(value.to_string());
        }
        let key_id = key_id
            .filter(|id| is_key_id(id))
            .ok_or_else(|| "the ask proof names no key id".to_string())?;
        let to = to
            .filter(|to| !to.is_empty())
            .ok_or_else(|| "the ask proof names no recipient".to_string())?;
        let expires_at = expires_at
            .and_then(|exp| exp.parse::<u64>().ok())
            .ok_or_else(|| "the ask proof has no expiry".to_string())?;
        let nonce = nonce
            .filter(|nonce| is_nonce(nonce))
            .ok_or_else(|| "the ask proof has no nonce".to_string())?;
        let signature = signature
            .filter(|sig| !sig.is_empty())
            .ok_or_else(|| "the ask proof has no signature".to_string())?;
        Ok(Self {
            key_id,
            to,
            expires_at,
            nonce,
            signature,
        })
    }
}

fn is_key_id(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_nonce(text: &str) -> bool {
    (32..=64).contains(&text.len()) && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn proof_in(scope: Option<&str>) -> Option<Result<AskProof, String>> {
    let mut words = scope?
        .split_whitespace()
        .filter(|word| word.starts_with(PROOF_PREFIX));
    let first = words.next()?;
    if words.next().is_some() {
        return Some(Err("the ask carries two proofs".to_string()));
    }
    Some(AskProof::parse(first))
}

pub fn is_signed(scope: Option<&str>) -> bool {
    matches!(proof_in(scope), Some(Ok(_)))
}

pub fn party_word(scope: Option<&str>) -> Option<&str> {
    scope?
        .split_whitespace()
        .find(|word| PartyScope::parse(word).is_some())
}

pub fn recipient(host: &str, agent: &str) -> String {
    format!(
        "{}/{}",
        host.trim().to_ascii_lowercase(),
        agent.trim().to_ascii_lowercase()
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Signed<'a> {
    pub to: &'a str,
    pub from: &'a str,
    pub kind: &'a str,
    pub scope: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
}

pub fn payload(fields: &Signed<'_>, key_id: &str, expires_at: u64, nonce: &str) -> String {
    [
        PAYLOAD_VERSION.to_string(),
        format!("to={}", fields.to),
        format!("from={}", fields.from),
        format!("kind={}", fields.kind),
        format!("key={key_id}"),
        format!("exp={expires_at}"),
        format!("nonce={nonce}"),
        format!("scope={}", fields.scope),
        format!("redirect_uri={}", fields.redirect_uri),
        format!("code_challenge={}", fields.code_challenge),
    ]
    .join("\n")
}

pub fn key_id_of(sec1: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(sec1).into();
    encode_hex(&digest)
}

pub fn fresh_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

pub fn sign_with_identity(identity: &DeviceIdentity, fields: &Signed<'_>, now: u64) -> AskProof {
    let key_id = identity.device_id().to_hex();
    let expires_at = now + ASK_LIFETIME_SECS;
    let nonce = fresh_nonce();
    let sig = identity.sign(payload(fields, &key_id, expires_at, &nonce).as_bytes());
    AskProof {
        key_id,
        to: fields.to.to_string(),
        expires_at,
        nonce,
        signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    }
}

pub trait KeyBook: Send + Sync {
    fn key(&self, user: &str, key_id: &str) -> Result<Option<Vec<u8>>, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskSender {
    Verified { address: String, key_id: String },
    Unsigned { claimed: String },
}

impl AskSender {
    pub fn verified_address(&self) -> Option<&str> {
        match self {
            Self::Verified { address, .. } => Some(address),
            Self::Unsigned { .. } => None,
        }
    }

    pub fn is_allowlisted<'a>(&self, allowlist: impl IntoIterator<Item = &'a str>) -> bool {
        let Some(address) = self.verified_address() else {
            return false;
        };
        allowlist
            .into_iter()
            .any(|allowed| allowed.trim().eq_ignore_ascii_case(address))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskRefusal {
    Unsigned,
    Malformed(String),
    WrongRecipient { signed_for: String, here: String },
    Expired,
    TooLong,
    UnknownKey,
    KeyMismatch,
    BadSignature,
    Replayed,
    Unchecked(String),
}

impl std::fmt::Display for AskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsigned => f.write_str(
                "this ask is not signed, and unsigned asks are no longer accepted: update Proxy                  on the Mac that sent it",
            ),
            Self::Malformed(why) => write!(f, "this ask's proof cannot be read: {why}"),
            Self::WrongRecipient { signed_for, here } => {
                write!(f, "this ask was signed for {signed_for}, not {here}")
            }
            Self::Expired => f.write_str("this ask has expired"),
            Self::TooLong => f.write_str("this ask claims to last longer than an ask lasts"),
            Self::UnknownKey => {
                f.write_str("the key this ask is signed with is not a key of the address it names")
            }
            Self::KeyMismatch => f.write_str("proxy.ing answered a key that is not the one named"),
            Self::BadSignature => f.write_str("this ask's signature does not check out"),
            Self::Replayed => f.write_str("this ask was already sent once"),
            Self::Unchecked(why) => write!(f, "this ask's signature could not be checked: {why}"),
        }
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub fn verify_party_ask_signature(
    now_secs: u64,
    keys: &dyn KeyBook,
    ask: &Ask,
    here: &str,
    party: &PartyScope,
) -> Result<(AskSender, Option<AskProof>), AskRefusal> {
    let proof = match proof_in(ask.scope.as_deref()) {
        None if now_secs < UNSIGNED_ASKS_UNTIL => {
            return Ok((
                AskSender::Unsigned {
                    claimed: party.host.clone(),
                },
                None,
            ));
        }
        None => return Err(AskRefusal::Unsigned),
        Some(Err(why)) => return Err(AskRefusal::Malformed(why)),
        Some(Ok(proof)) => proof,
    };
    let to = recipient(here, &party.agent);
    if proof.to != to {
        return Err(AskRefusal::WrongRecipient {
            signed_for: proof.to,
            here: to,
        });
    }
    if now_secs > proof.expires_at {
        return Err(AskRefusal::Expired);
    }
    if proof.expires_at > now_secs + ASK_LIFETIME_SECS + CLOCK_SKEW_SECS {
        return Err(AskRefusal::TooLong);
    }
    let sender = AgentAddress::parse(&party.host)
        .ok()
        .filter(|sender| sender.agent.is_none() && sender.host() == party.host)
        .ok_or_else(|| AskRefusal::Malformed("its host is not an address".to_string()))?;
    let scope_word = party_word(ask.scope.as_deref())
        .ok_or_else(|| AskRefusal::Malformed("it names no party".to_string()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(AskRefusal::BadSignature)?;
    let key = match keys.key(&sender.user, &proof.key_id) {
        Ok(Some(key)) => key,
        Ok(None) => return Err(AskRefusal::UnknownKey),
        Err(why) => return Err(AskRefusal::Unchecked(why)),
    };
    if key_id_of(&key) != proof.key_id {
        return Err(AskRefusal::KeyMismatch);
    }
    let key = VerifyingKey::from_sec1_bytes(&key).map_err(|_| AskRefusal::KeyMismatch)?;
    let message = payload(
        &Signed {
            to: &to,
            from: &party.host,
            kind: KIND_SEAT,
            scope: scope_word,
            redirect_uri: &ask.redirect_uri,
            code_challenge: &ask.code_challenge,
        },
        &proof.key_id,
        proof.expires_at,
        &proof.nonce,
    );
    DeviceIdentity::verify(&key, message.as_bytes(), &signature)
        .map_err(|_| AskRefusal::BadSignature)?;
    let verified = AskSender::Verified {
        address: sender.host(),
        key_id: proof.key_id.clone(),
    };
    Ok((verified, Some(proof)))
}

#[cfg(feature = "sqlite")]
pub fn first_sighting_conn(
    conn: &rusqlite::Connection,
    nonce: &str,
    key_id: &str,
    now_secs: u64,
) -> Result<bool, crate::sqlite::SqliteError> {
    let now_i64 = i64::try_from(now_secs).unwrap_or(i64::MAX);
    let forget_before = now_i64.saturating_sub(NONCE_MEMORY_SECS as i64);
    conn.execute(
        "DELETE FROM ask_nonces WHERE seen_at < ?1",
        rusqlite::params![forget_before],
    )
    .map_err(|error| {
        crate::sqlite::SqliteError::Other(format!("forget old ask nonces: {error}"))
    })?;
    let added = conn
        .execute(
            "INSERT OR IGNORE INTO ask_nonces (nonce, key_id, seen_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![nonce, key_id, now_i64],
        )
        .map_err(|error| {
            crate::sqlite::SqliteError::Other(format!("note an ask nonce: {error}"))
        })?;
    Ok(added == 1)
}
