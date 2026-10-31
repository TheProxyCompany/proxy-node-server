//! Row-shaped replication ops. The op payload is a table name, a primary key,
//! and a mutation carrying the full column image (upsert) or a delete — never
//! SQL text. Row-shaped ops are idempotent, last-write-wins resolvable per row
//! by HLC, and survive additive schema changes. Encoded with `postcard`,
//! matching the crate's envelope codec.

use serde::{Deserialize, Serialize};

use crate::op::StoreId;

/// Default namespace a relational row store claims in the shared op-log.
pub const STORE_ID: &str = "proxydb";

/// `origin` column: an op minted by this device, served to peers as ours.
pub const ORIGIN_LOCAL: i64 = 1;
/// `origin` column: an op pulled from a peer, relayed verbatim.
pub const ORIGIN_REMOTE: i64 = 0;

/// Field separator for the denormalized `row_pk` index projection. Unit
/// separator (0x1f) never appears in a text primary key, so composite keys
/// serialize unambiguously.
const PK_SEP: char = '\u{1f}';

/// The default relational row store namespace.
pub fn store_id() -> StoreId {
    StoreId::new(STORE_ID).expect("\"proxydb\" is a valid store id")
}

/// A relational scalar, serde-encodable so it round-trips through an op payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Scalar {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Scalar {
    /// Stable text rendering for the `row_pk` index projection.
    pub fn render(&self) -> String {
        match self {
            Scalar::Null => String::new(),
            Scalar::Int(v) => v.to_string(),
            Scalar::Real(v) => format!("{v:?}"),
            Scalar::Text(v) => v.clone(),
            Scalar::Blob(v) => encode_hex_lower(v),
        }
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// One primary-key column and its value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyField {
    pub col: String,
    pub val: Scalar,
}

/// One data column and its value in a full-row image.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub value: Scalar,
}

/// Row mutation: a full-column image to write, or a delete.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Mutation {
    Upsert { columns: Vec<Column> },
    Delete,
}

/// A row-shaped op: which row of which table changed, and how.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyDbOp {
    pub table: String,
    pub key: Vec<KeyField>,
    pub mutation: Mutation,
}

/// Canonical unversioned alias for [`ProxyDbOp`].
pub type RowOp = ProxyDbOp;

/// [`ProxyDbOp::row_pk`] for a key given as column/value pairs, before any op
/// exists — the emission and reconcile paths use this to look a row up in the
/// LWW index.
pub fn row_pk_of(key: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (_, val)) in key.iter().enumerate() {
        if i > 0 {
            out.push(PK_SEP);
        }
        out.push_str(val);
    }
    out
}

impl ProxyDbOp {
    /// Denormalized primary key for the LWW index: the key values rendered and
    /// joined by the unit separator.
    pub fn row_pk(&self) -> String {
        let mut out = String::new();
        for (i, field) in self.key.iter().enumerate() {
            if i > 0 {
                out.push(PK_SEP);
            }
            out.push_str(&field.val.render());
        }
        out
    }

    pub fn encode_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn decode_bytes(payload: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(payload)
    }
}

/// SQLite identifiers are interpolated into statements (table + column names
/// come from ops), so they must be validated: ASCII alphanumeric plus
/// underscore, non-empty.
pub fn is_valid_ident(ident: &str) -> bool {
    !ident.is_empty()
        && ident
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
