//! SQLite-backed [`crate::log::LogSource`] queries over `oplog_db`.

use crate::{RelayLogEntry, RelayLogPage, RelayStreamState};

use super::oplog;

/// Cumulative envelope bytes one relay page may carry (4 MiB).
pub const RELAY_PAGE_MAX_BYTES: usize = 4 * 1024 * 1024;

pub fn relay_state_conn(conn: &rusqlite::Connection) -> Result<Option<RelayStreamState>, String> {
    let state = oplog::relay_stream_state(conn).map_err(|error| error.to_string())?;
    Ok(Some(RelayStreamState {
        epoch: state.stream_epoch,
        head: state.head_seq,
        floor: state.compacted_through_seq,
    }))
}

pub fn relay_page_conn(
    conn: &rusqlite::Connection,
    after: u64,
    limit: usize,
) -> Result<Option<RelayLogPage>, String> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let state = oplog::relay_stream_state(&tx).map_err(|error| error.to_string())?;
    let mut total = 0usize;
    let mut entries = Vec::new();
    for (seq, op, envelope) in
        oplog::relay_since_with_envelopes(&tx, after, limit).map_err(|error| error.to_string())?
    {
        if !entries.is_empty() && total + envelope.len() > RELAY_PAGE_MAX_BYTES {
            break;
        }
        total += envelope.len();
        entries.push(RelayLogEntry { seq, op });
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(Some(RelayLogPage {
        state: RelayStreamState {
            epoch: state.stream_epoch,
            head: state.head_seq,
            floor: state.compacted_through_seq,
        },
        entries,
    }))
}
