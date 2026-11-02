//! Per-peer replication scope (`Full` or `Restricted { stores, tables }`).

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::op::SignedOp;
use crate::row_op::{ProxyDbOp, STORE_ID as PROXYDB_STORE_ID, is_valid_ident};

pub const SCOPE_FULL: &str = "full";
pub const TRELLIS_STORE_ID: &str = "trellis";

#[derive(Clone, Debug, PartialEq)]
pub enum MeshScope {
    Full,
    Restricted {
        stores: BTreeSet<String>,
        tables: Option<BTreeSet<String>>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedShape {
    stores: BTreeSet<String>,
    tables: Option<BTreeSet<String>>,
}

impl MeshScope {
    pub fn parse_raw(raw: &str) -> Result<Self, String> {
        if raw == SCOPE_FULL {
            return Ok(Self::Full);
        }
        let shape: RestrictedShape =
            serde_json::from_str(raw).map_err(|e| format!("mesh scope: {e}"))?;
        if shape.stores.is_empty() {
            return Err("mesh scope: stores must be non-empty".to_string());
        }
        for store in &shape.stores {
            if store != PROXYDB_STORE_ID && store != TRELLIS_STORE_ID {
                return Err(format!("mesh scope: unknown store '{store}'"));
            }
        }
        if let Some(tables) = &shape.tables {
            if tables.is_empty() {
                return Err("mesh scope: tables must be non-empty when present".to_string());
            }
            if !shape.stores.contains(PROXYDB_STORE_ID) {
                return Err(format!(
                    "mesh scope: tables only restrict the '{PROXYDB_STORE_ID}' store"
                ));
            }
            for table in tables {
                if !is_valid_ident(table) {
                    return Err(format!("mesh scope: invalid table name '{table}'"));
                }
            }
        }
        Ok(Self::Restricted {
            stores: shape.stores,
            tables: shape.tables,
        })
    }

    pub fn parse_lossy(raw: &str) -> Self {
        Self::parse_raw(raw).unwrap_or(Self::Full)
    }

    pub fn admits_op(&self, op: &SignedOp) -> Result<bool, String> {
        let Self::Restricted { stores, tables } = self else {
            return Ok(true);
        };
        let store = op.body.store.as_str();
        if !stores.contains(store) {
            return Ok(false);
        }
        match tables {
            Some(tables) if store == PROXYDB_STORE_ID => Ok(tables.contains(
                &ProxyDbOp::decode_bytes(&op.body.payload)
                    .map_err(|e| format!("decode proxydb op: {e}"))?
                    .table,
            )),
            _ => Ok(true),
        }
    }
}
