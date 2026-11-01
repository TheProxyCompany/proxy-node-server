#![allow(clippy::collapsible_if, clippy::type_complexity)]
//! SQLite-backed op-log, materialized LWW heads (`oplog_heads`), per-origin
//! coverage (`mesh_origin_coverage`), and pending-edge / callback outbox tables.

pub mod coverage;
pub mod device_book;
pub mod log_source;
pub mod oplog;
pub mod oplog_heads;
pub mod oplog_queries;
pub mod pending_edges;
pub mod retention;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SqliteError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Other(String),
}
#[cfg(feature = "pull-http")]
pub mod pull_socket;
pub mod quarantine;
