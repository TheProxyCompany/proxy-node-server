//! Generic SQLite relational row-store and row-reconcile engine (`RowOp` apply,
//! `OpBatch` emission, full-row image reads, and keyset row reconciliation).

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex as StdMutex, OnceLock};

use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};

use super::SqliteError;
use super::oplog;
use crate::identity::DeviceId;
use crate::op::OrderKey;
use crate::row_op::{Column, KeyField, Mutation, ProxyDbOp, Scalar, is_valid_ident, row_pk_of};

pub const ROW_RECONCILE_REPAIR_VERSION: u32 = 1;
pub const CHUNK_ROWS: usize = 128;

pub trait ScalarSqlExt {
    fn into_sql(self) -> SqlValue;
    fn from_sql(v: ValueRef<'_>) -> Scalar;
}

impl ScalarSqlExt for Scalar {
    fn into_sql(self) -> SqlValue {
        match self {
            Scalar::Null => SqlValue::Null,
            Scalar::Int(i) => SqlValue::Integer(i),
            Scalar::Real(f) => SqlValue::Real(f),
            Scalar::Text(s) => SqlValue::Text(s),
            Scalar::Blob(b) => SqlValue::Blob(b),
        }
    }

    fn from_sql(v: ValueRef<'_>) -> Scalar {
        match v {
            ValueRef::Null => Scalar::Null,
            ValueRef::Integer(i) => Scalar::Int(i),
            ValueRef::Real(f) => Scalar::Real(f),
            ValueRef::Text(bytes) => Scalar::Text(String::from_utf8_lossy(bytes).into_owned()),
            ValueRef::Blob(bytes) => Scalar::Blob(bytes.to_vec()),
        }
    }
}

pub struct FkSuspendGuard<'a> {
    conn: &'a rusqlite::Connection,
}

impl<'a> FkSuspendGuard<'a> {
    pub fn for_mutation(
        conn: &'a rusqlite::Connection,
        mutation: &Mutation,
    ) -> Result<Option<Self>, SqliteError> {
        match mutation {
            Mutation::Upsert { .. } => {
                conn.execute_batch("PRAGMA foreign_keys = OFF;")
                    .map_err(|e| SqliteError::Other(format!("mesh fk suspend: {e}")))?;
                Ok(Some(Self { conn }))
            }
            Mutation::Delete => Ok(None),
        }
    }
}

impl Drop for FkSuspendGuard<'_> {
    fn drop(&mut self) {
        let _ = self.conn.execute_batch("PRAGMA foreign_keys = ON;");
    }
}

pub fn write_row_if_newer(
    conn: &rusqlite::Connection,
    store_id: &str,
    op: &ProxyDbOp,
    order_key: OrderKey,
    device_local_tables: &[&str],
) -> Result<bool, SqliteError> {
    let newest =
        oplog::newest_applied_in_store(conn, store_id, &op.table, &op.row_pk(), &order_key.op_id)?;
    if newest.is_some_and(|current| order_key <= current) {
        return Ok(false);
    }
    write_row(conn, op, device_local_tables)
}

pub fn upsert_matches_current_row(
    conn: &rusqlite::Connection,
    op: &ProxyDbOp,
    columns: &[&Column],
) -> Result<bool, SqliteError> {
    let select = columns
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let clause = op
        .key
        .iter()
        .enumerate()
        .map(|(i, f)| format!("{} = ?{}", f.col, i + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let sql = format!("SELECT {select} FROM {} WHERE {clause}", op.table);
    let key_values = op
        .key
        .iter()
        .map(|f| f.val.clone().into_sql())
        .collect::<Vec<_>>();
    conn.prepare_cached(&sql)
        .and_then(|mut stmt| {
            stmt.query_row(params_from_iter(key_values), |row| {
                for (i, column) in columns.iter().enumerate() {
                    if Scalar::from_sql(row.get_ref(i)?) != column.value {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .optional()
        })
        .map(|matched| matched.unwrap_or(false))
        .map_err(|e| SqliteError::Other(format!("mesh row compare {}: {e}", op.table)))
}

pub fn local_table_columns(
    conn: &rusqlite::Connection,
    table: &str,
) -> Result<Option<HashSet<String>>, SqliteError> {
    let mut stmt = conn
        .prepare_cached(&format!("PRAGMA table_info({table})"))
        .map_err(|e| SqliteError::Other(format!("mesh table probe {table}: {e}")))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .and_then(|rows| rows.collect::<Result<HashSet<_>, _>>())
        .map_err(|e| SqliteError::Other(format!("mesh table probe {table}: {e}")))?;
    Ok((!columns.is_empty()).then_some(columns))
}

fn log_schema_drift_skip(table: &str, _detail: &str) {
    static SEEN: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| StdMutex::new(HashSet::new()));
    let _ = seen.lock().map(|mut seen| seen.insert(table.to_string()));
}

pub fn write_row(
    conn: &rusqlite::Connection,
    op: &ProxyDbOp,
    device_local_tables: &[&str],
) -> Result<bool, SqliteError> {
    if !is_valid_ident(&op.table) {
        return Err(SqliteError::Other(format!(
            "invalid table name: {}",
            op.table
        )));
    }
    if device_local_tables.contains(&op.table.as_str()) {
        return Ok(false);
    }
    let Some(local_columns) = local_table_columns(conn, &op.table)? else {
        log_schema_drift_skip(&op.table, "table missing locally");
        return Ok(false);
    };
    match &op.mutation {
        Mutation::Upsert { columns } => {
            for column in columns {
                if !is_valid_ident(&column.name) {
                    return Err(SqliteError::Other(format!(
                        "invalid column: {}",
                        column.name
                    )));
                }
            }
            for field in &op.key {
                if !is_valid_ident(&field.col) {
                    return Err(SqliteError::Other(format!(
                        "invalid key column: {}",
                        field.col
                    )));
                }
            }
            if op.key.iter().any(|f| !local_columns.contains(&f.col)) {
                log_schema_drift_skip(&op.table, "key column missing locally");
                return Ok(false);
            }
            let columns = columns
                .iter()
                .filter(|c| local_columns.contains(&c.name))
                .collect::<Vec<_>>();
            if columns.is_empty() {
                log_schema_drift_skip(&op.table, "no op column exists locally");
                return Ok(false);
            }
            if upsert_matches_current_row(conn, op, &columns)? {
                return Ok(false);
            }
            let names = columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = (1..=columns.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(", ");
            let conflict_target = op
                .key
                .iter()
                .map(|f| f.col.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let assignments = columns
                .iter()
                .filter(|c| !op.key.iter().any(|f| f.col == c.name))
                .map(|c| format!("{} = excluded.{}", c.name, c.name))
                .collect::<Vec<_>>();
            let sql = if assignments.is_empty() {
                format!(
                    "INSERT INTO {} ({names}) VALUES ({placeholders})
                     ON CONFLICT ({conflict_target}) DO NOTHING",
                    op.table
                )
            } else {
                format!(
                    "INSERT INTO {} ({names}) VALUES ({placeholders})
                     ON CONFLICT ({conflict_target}) DO UPDATE SET {}",
                    op.table,
                    assignments.join(", ")
                )
            };
            let values = columns
                .iter()
                .map(|c| c.value.clone().into_sql())
                .collect::<Vec<_>>();
            match conn
                .prepare_cached(&sql)
                .and_then(|mut stmt| stmt.execute(params_from_iter(values)))
            {
                Ok(_) => Ok(true),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
                {
                    Ok(false)
                }
                Err(e) => Err(SqliteError::Other(format!("mesh upsert {}: {e}", op.table))),
            }
        }
        Mutation::Delete => {
            for field in &op.key {
                if !is_valid_ident(&field.col) {
                    return Err(SqliteError::Other(format!(
                        "invalid key column: {}",
                        field.col
                    )));
                }
            }
            if op.key.iter().any(|f| !local_columns.contains(&f.col)) {
                log_schema_drift_skip(&op.table, "key column missing locally");
                return Ok(false);
            }
            let clause = op
                .key
                .iter()
                .enumerate()
                .map(|(i, f)| format!("{} = ?{}", f.col, i + 1))
                .collect::<Vec<_>>()
                .join(" AND ");
            let sql = format!("DELETE FROM {} WHERE {clause}", op.table);
            let values = op
                .key
                .iter()
                .map(|f| f.val.clone().into_sql())
                .collect::<Vec<_>>();
            match conn
                .prepare_cached(&sql)
                .and_then(|mut stmt| stmt.execute(params_from_iter(values)))
            {
                Ok(_) => Ok(true),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY =>
                {
                    Ok(false)
                }
                Err(e) => Err(SqliteError::Other(format!("mesh delete {}: {e}", op.table))),
            }
        }
    }
}

pub fn image_matches(logged: &[Column], live: &[Column]) -> bool {
    if logged.len() != live.len() {
        return false;
    }
    let logged: HashMap<&str, &Scalar> = logged
        .iter()
        .map(|column| (column.name.as_str(), &column.value))
        .collect();
    live.iter()
        .all(|column| logged.get(column.name.as_str()) == Some(&&column.value))
}

pub fn material_image_matches(logged: &[Column], live: &[Column], volatile: &[&str]) -> bool {
    if volatile.is_empty() {
        return image_matches(logged, live);
    }
    let material = |columns: &[Column]| {
        columns
            .iter()
            .filter(|column| !volatile.contains(&column.name.as_str()))
            .cloned()
            .collect::<Vec<_>>()
    };
    image_matches(&material(logged), &material(live))
}

pub fn read_row_image(
    conn: &rusqlite::Connection,
    table: &str,
    id_col: &str,
    id: &str,
) -> Result<Option<Vec<Column>>, SqliteError> {
    read_row_image_keyed(conn, table, &[(id_col, id)])
}

pub fn read_row_image_keyed(
    conn: &rusqlite::Connection,
    table: &str,
    key: &[(&str, &str)],
) -> Result<Option<Vec<Column>>, SqliteError> {
    if !is_valid_ident(table) || key.iter().any(|(col, _)| !is_valid_ident(col)) {
        return Err(SqliteError::Other(format!("invalid identifier on {table}")));
    }
    let clause = key
        .iter()
        .enumerate()
        .map(|(i, (col, _))| format!("{col} = ?{}", i + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let sql = format!("SELECT * FROM {table} WHERE {clause}");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| SqliteError::Other(format!("row image prepare {table}: {e}")))?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt
        .query(params_from_iter(key.iter().map(|(_, val)| *val)))
        .map_err(|e| SqliteError::Other(format!("row image query {table}: {e}")))?;
    let Some(row) = rows
        .next()
        .map_err(|e| SqliteError::Other(format!("row image row {table}: {e}")))?
    else {
        return Ok(None);
    };
    let mut columns = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let value = row
            .get_ref(i)
            .map_err(|e| SqliteError::Other(format!("row image col {name}: {e}")))?;
        columns.push(Column {
            name: name.clone(),
            value: Scalar::from_sql(value),
        });
    }
    Ok(Some(columns))
}

pub fn read_row_images_chunk(
    conn: &rusqlite::Connection,
    table: &str,
    key_cols: &[&str],
    chunk: &[Vec<String>],
) -> Result<HashMap<String, Vec<Column>>, SqliteError> {
    if chunk.is_empty() {
        return Ok(HashMap::new());
    }
    if !is_valid_ident(table) || key_cols.iter().any(|col| !is_valid_ident(col)) {
        return Err(SqliteError::Other(format!(
            "invalid identifier in row reconcile chunk for {table}"
        )));
    }
    let mut parameter = 1usize;
    let predicates = chunk
        .iter()
        .map(|_| {
            let terms = key_cols
                .iter()
                .map(|col| {
                    let term = format!("{col} = ?{parameter}");
                    parameter += 1;
                    term
                })
                .collect::<Vec<_>>()
                .join(" AND ");
            format!("({terms})")
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let sql = format!("SELECT * FROM {table} WHERE {predicates}");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| SqliteError::Other(format!("row reconcile chunk prepare {table}: {e}")))?;
    let names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|name| name.to_string())
        .collect();
    let key_indexes = key_cols
        .iter()
        .map(|key_col| {
            names
                .iter()
                .position(|name| name == key_col)
                .ok_or_else(|| {
                    SqliteError::Other(format!(
                        "row reconcile key column {key_col} missing from {table}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parameters = chunk.iter().flat_map(|key| key.iter());
    let mut rows = stmt
        .query(params_from_iter(parameters))
        .map_err(|e| SqliteError::Other(format!("row reconcile chunk query {table}: {e}")))?;
    let mut images = HashMap::with_capacity(chunk.len());
    while let Some(row) = rows
        .next()
        .map_err(|e| SqliteError::Other(format!("row reconcile chunk row {table}: {e}")))?
    {
        let key_values = key_indexes
            .iter()
            .map(|index| row.get::<_, String>(*index))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| SqliteError::Other(format!("row reconcile chunk key {table}: {e}")))?;
        let key = key_cols
            .iter()
            .zip(&key_values)
            .map(|(column, value)| (*column, value.as_str()))
            .collect::<Vec<_>>();
        let mut columns = Vec::with_capacity(names.len());
        for (index, name) in names.iter().enumerate() {
            let value = row.get_ref(index).map_err(|e| {
                SqliteError::Other(format!("row reconcile chunk column {table}.{name}: {e}"))
            })?;
            columns.push(Column {
                name: name.clone(),
                value: Scalar::from_sql(value),
            });
        }
        images.insert(row_pk_of(&key), columns);
    }
    Ok(images)
}

pub fn table_key_page(
    conn: &rusqlite::Connection,
    table: &str,
    key_cols: &[&str],
    after: &[String],
    limit: usize,
) -> Result<Vec<Vec<String>>, SqliteError> {
    if !is_valid_ident(table) || key_cols.iter().any(|column| !is_valid_ident(column)) {
        return Err(SqliteError::Other(format!(
            "invalid identifier in row reconcile scan for {table}"
        )));
    }
    if !after.is_empty() && after.len() != key_cols.len() {
        return Err(SqliteError::Other(format!(
            "row reconcile cursor for {table} has {} values for {} key columns",
            after.len(),
            key_cols.len()
        )));
    }
    let cols = key_cols.join(", ");
    let (predicate, limit_parameter) = if after.is_empty() {
        (String::new(), 1)
    } else if key_cols.len() == 1 {
        (format!(" WHERE {} > ?1", key_cols[0]), 2)
    } else {
        let parameters = (1..=key_cols.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        (
            format!(" WHERE ({cols}) > ({parameters})"),
            key_cols.len() + 1,
        )
    };
    let sql =
        format!("SELECT {cols} FROM {table}{predicate} ORDER BY {cols} LIMIT ?{limit_parameter}");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| SqliteError::Other(format!("row reconcile scan {table}: {e}")))?;
    let mut parameters: Vec<SqlValue> = after.iter().cloned().map(SqlValue::Text).collect();
    parameters.push(SqlValue::Integer(limit as i64));
    let rows = stmt
        .query_map(params_from_iter(parameters), |row| {
            (0..key_cols.len())
                .map(|i| row.get::<_, String>(i))
                .collect::<rusqlite::Result<Vec<String>>>()
        })
        .map_err(|e| SqliteError::Other(format!("row reconcile scan {table}: {e}")))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| SqliteError::Other(format!("row reconcile scan {table}: {e}")))
}

pub fn delete_row(
    conn: &rusqlite::Connection,
    table: &str,
    key: &[(&str, &str)],
) -> Result<(), SqliteError> {
    let clause = key
        .iter()
        .enumerate()
        .map(|(i, (col, _))| format!("{col} = ?{}", i + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    let sql = format!("DELETE FROM {table} WHERE {clause}");
    conn.execute(&sql, params_from_iter(key.iter().map(|(_, val)| *val)))
        .map_err(|e| SqliteError::Other(format!("row reconcile tombstone finish {table}: {e}")))?;
    Ok(())
}

pub fn key_fields(key: &[(&str, &str)]) -> Vec<KeyField> {
    key.iter()
        .map(|(col, val)| KeyField {
            col: col.to_string(),
            val: Scalar::Text(val.to_string()),
        })
        .collect()
}

#[derive(Default)]
pub struct OpBatch {
    pub records: Vec<ProxyDbOp>,
}

impl OpBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, table: impl Into<String>, key: Vec<KeyField>, columns: Vec<Column>) {
        self.records.push(ProxyDbOp {
            table: table.into(),
            key,
            mutation: Mutation::Upsert { columns },
        });
    }

    pub fn delete(&mut self, table: impl Into<String>, key: Vec<KeyField>) {
        self.records.push(ProxyDbOp {
            table: table.into(),
            key,
            mutation: Mutation::Delete,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RowSweep {
    pub minted: usize,
    pub deleted: usize,
    pub deferred: bool,
}

impl RowSweep {
    pub fn is_noop(&self) -> bool {
        self.minted == 0 && self.deleted == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowSweepStep {
    Advanced { minted: usize, deleted: usize },
    Complete,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowReconcilePhase {
    Tombstones,
    Mint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowReconcileCursor {
    pub version: u32,
    pub phase: RowReconcilePhase,
    pub table_index: usize,
    pub after: Vec<String>,
}

impl RowReconcileCursor {
    pub fn initial() -> Self {
        Self {
            version: ROW_RECONCILE_REPAIR_VERSION,
            phase: RowReconcilePhase::Tombstones,
            table_index: 0,
            after: Vec::new(),
        }
    }

    pub fn is_valid(&self, tables: &[(&str, &[&str])]) -> bool {
        if self.version != ROW_RECONCILE_REPAIR_VERSION || self.table_index > tables.len() {
            return false;
        }
        if self.table_index == tables.len() {
            return self.after.is_empty();
        }
        self.after.is_empty() || self.after.len() == tables[self.table_index].1.len()
    }
}

pub fn note_peer_drained(
    conn: &rusqlite::Connection,
    peer: &DeviceId,
    now_rfc3339: &str,
) -> Result<(), SqliteError> {
    conn.execute(
        "INSERT INTO oplog_db.mesh_pull_drains (peer_device_id, drained_at)
         VALUES (?1, ?2)
         ON CONFLICT(peer_device_id) DO UPDATE SET drained_at = excluded.drained_at",
        params![peer.as_bytes().as_slice(), now_rfc3339],
    )
    .map_err(|e| SqliteError::Other(format!("note peer drained: {e}")))?;
    Ok(())
}

pub enum RowDivergence {
    Covered,
    Uncovered,
    Tombstoned,
}

pub fn row_divergence(
    newest_payload: Option<&[u8]>,
    live: &[Column],
    volatile: &[&str],
) -> Result<RowDivergence, SqliteError> {
    match newest_payload {
        None => Ok(RowDivergence::Uncovered),
        Some(payload) => match ProxyDbOp::decode_bytes(payload)
            .map_err(|e| SqliteError::Other(format!("decode row op: {e}")))?
            .mutation
        {
            Mutation::Upsert { columns } if material_image_matches(&columns, live, volatile) => {
                Ok(RowDivergence::Covered)
            }
            Mutation::Upsert { .. } => Ok(RowDivergence::Uncovered),
            Mutation::Delete => Ok(RowDivergence::Tombstoned),
        },
    }
}
