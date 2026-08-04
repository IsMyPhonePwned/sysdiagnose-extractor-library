//! Best-effort SQLite → JSON helpers (approximates SAF `sqlite2json` usage).
//!
//! Native targets use `rusqlite` (bundled). On `wasm32-unknown-unknown`,
//! [`sqlite-wasm-rs`](https://crates.io/crates/sqlite-wasm-rs) opens DB bytes via
//! `sqlite3_deserialize` so App Info / table dumps work in the browser.

use serde_json::{json, Map, Value};

/// Dump all user tables to a JSON object `{ table_name: [ rows as objects ] }`.
pub fn dump_sqlite_bytes(
    data: &[u8],
    max_rows_per_table: usize,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let tables = list_user_tables(data)?;
    let mut out = Map::new();
    for table in tables {
        if !table.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let sql = if max_rows_per_table == 0 {
            format!("SELECT * FROM \"{table}\"")
        } else {
            format!("SELECT * FROM \"{table}\" LIMIT {max_rows_per_table}")
        };
        match query_sqlite_select(data, &sql) {
            Ok(rows) => {
                out.insert(
                    table,
                    Value::Array(rows.into_iter().map(Value::Object).collect()),
                );
            }
            Err(_) => continue,
        }
    }
    Ok(Value::Object(out))
}

/// Run a single SQL statement that returns rows (typically `SELECT …`).
pub(crate) fn query_sqlite_select(
    data: &[u8],
    sql: &str,
) -> Result<Vec<Map<String, Value>>, Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        query_sqlite_select_native(data, sql)
    }
    #[cfg(target_arch = "wasm32")]
    {
        query_sqlite_select_wasm(data, sql)
    }
}

fn list_user_tables(
    data: &[u8],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let rows = query_sqlite_select(
        data,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
    )?;
    Ok(rows
        .into_iter()
        .filter_map(|m| {
            m.get("name")
                .or_else(|| m.values().next())
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .collect())
}

#[cfg(not(target_arch = "wasm32"))]
fn query_sqlite_select_native(
    data: &[u8],
    sql: &str,
) -> Result<Vec<Map<String, Value>>, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;

    use rusqlite::Connection;

    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(data)?;
    let conn = Connection::open(tmp.path())?;
    let mut stmt = conn.prepare(sql)?;
    let ncols = stmt.column_count();
    let colnames: Vec<String> = (0..ncols)
        .map(|i| stmt.column_name(i).unwrap_or("").to_string())
        .collect();
    let mut rows = Vec::new();
    let mut q = stmt.query([])?;
    while let Some(row) = q.next()? {
        let mut obj = Map::new();
        for i in 0..ncols {
            let key = colnames
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("col{i}"));
            obj.insert(key, value_ref_to_json(row.get_ref(i)?));
        }
        rows.push(obj);
    }
    Ok(rows)
}

#[cfg(target_arch = "wasm32")]
fn query_sqlite_select_wasm(
    data: &[u8],
    sql: &str,
) -> Result<Vec<Map<String, Value>>, Box<dyn std::error::Error + Send + Sync>> {
    use std::ffi::{CStr, CString};

    use sqlite_wasm_rs as ffi;

    if data.len() < 16 {
        return Err("SQLite database too small".into());
    }

    unsafe {
        let mut db = std::ptr::null_mut();
        let open_rc = ffi::sqlite3_open_v2(
            c":memory:".as_ptr().cast(),
            &mut db,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
            std::ptr::null(),
        );
        if open_rc != ffi::SQLITE_OK as i32 {
            return Err(format!("sqlite3_open_v2 failed: {open_rc}").into());
        }

        let n = data.len();
        let ptr = ffi::sqlite3_malloc64(n as ffi::sqlite3_uint64) as *mut u8;
        if ptr.is_null() {
            ffi::sqlite3_close(db);
            return Err("sqlite3_malloc64 failed".into());
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, n);

        let deser_rc = ffi::sqlite3_deserialize(
            db,
            c"main".as_ptr().cast(),
            ptr,
            n as ffi::sqlite3_int64,
            n as ffi::sqlite3_int64,
            ffi::SQLITE_DESERIALIZE_READONLY | ffi::SQLITE_DESERIALIZE_FREEONCLOSE,
        );
        if deser_rc != ffi::SQLITE_OK as i32 {
            ffi::sqlite3_close(db);
            return Err(format!("sqlite3_deserialize failed: {deser_rc}").into());
        }

        let c_sql = CString::new(sql).map_err(|e| e.to_string())?;
        let mut stmt = std::ptr::null_mut();
        let mut tail = std::ptr::null();
        let prep_rc = ffi::sqlite3_prepare_v2(db, c_sql.as_ptr(), -1, &mut stmt, &mut tail);
        if prep_rc != ffi::SQLITE_OK as i32 {
            let msg = sqlite_errmsg(db);
            ffi::sqlite3_close(db);
            return Err(format!("sqlite3_prepare_v2 failed: {msg}").into());
        }

        let ncols = ffi::sqlite3_column_count(stmt);
        let mut colnames = Vec::with_capacity(ncols as usize);
        for i in 0..ncols {
            let name_ptr = ffi::sqlite3_column_name(stmt, i);
            let name = if name_ptr.is_null() {
                format!("col{i}")
            } else {
                CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
            };
            colnames.push(name);
        }

        let mut rows = Vec::new();
        loop {
            let step = ffi::sqlite3_step(stmt);
            if step == ffi::SQLITE_DONE as i32 {
                break;
            }
            if step != ffi::SQLITE_ROW as i32 {
                let msg = sqlite_errmsg(db);
                ffi::sqlite3_finalize(stmt);
                ffi::sqlite3_close(db);
                return Err(format!("sqlite3_step failed: {msg}").into());
            }
            let mut obj = Map::new();
            for i in 0..ncols {
                let key = colnames
                    .get(i as usize)
                    .cloned()
                    .unwrap_or_else(|| format!("col{i}"));
                obj.insert(key, wasm_column_to_json(stmt, i));
            }
            rows.push(obj);
        }

        ffi::sqlite3_finalize(stmt);
        ffi::sqlite3_close(db);
        Ok(rows)
    }
}

#[cfg(target_arch = "wasm32")]
unsafe fn sqlite_errmsg(db: *mut sqlite_wasm_rs::sqlite3) -> String {
    use std::ffi::CStr;
    let p = sqlite_wasm_rs::sqlite3_errmsg(db);
    if p.is_null() {
        "unknown sqlite error".into()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

#[cfg(target_arch = "wasm32")]
unsafe fn wasm_column_to_json(
    stmt: *mut sqlite_wasm_rs::sqlite3_stmt,
    i: i32,
) -> Value {
    use std::ffi::CStr;
    use sqlite_wasm_rs as ffi;

    match ffi::sqlite3_column_type(stmt, i) {
        t if t == ffi::SQLITE_INTEGER as i32 => json!(ffi::sqlite3_column_int64(stmt, i)),
        t if t == ffi::SQLITE_FLOAT as i32 => json!(ffi::sqlite3_column_double(stmt, i)),
        t if t == ffi::SQLITE_TEXT as i32 => {
            let p = ffi::sqlite3_column_text(stmt, i);
            if p.is_null() {
                Value::Null
            } else {
                Value::String(CStr::from_ptr(p.cast()).to_string_lossy().into_owned())
            }
        }
        t if t == ffi::SQLITE_BLOB as i32 => {
            let n = ffi::sqlite3_column_bytes(stmt, i);
            json!(format!("<{n} bytes binary>"))
        }
        _ => Value::Null,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn value_ref_to_json(v: rusqlite::types::ValueRef<'_>) -> Value {
    match v {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(i) => json!(i),
        rusqlite::types::ValueRef::Real(f) => json!(f),
        rusqlite::types::ValueRef::Text(t) => {
            Value::String(String::from_utf8_lossy(t).into_owned())
        }
        rusqlite::types::ValueRef::Blob(b) => blob_to_json_python_style(b),
    }
}

/// Approximate Python `sqlite2json` / `str(blob)` for non-text SQLite values.
#[cfg(not(target_arch = "wasm32"))]
fn blob_to_json_python_style(b: &[u8]) -> Value {
    let mut s = String::from("b'");
    for &byte in b {
        match byte {
            b'\\' => s.push_str("\\\\"),
            b'\'' => s.push_str("\\'"),
            0x20..=0x7e => s.push(byte as char),
            _ => s.push_str(&format!("\\x{byte:02x}")),
        }
    }
    s.push('\'');
    Value::String(s)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn dump_matches_sqlite2struct_shape() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, flag INTEGER);
             INSERT INTO items (name, flag) VALUES ('hello', 1);",
        )
        .unwrap();
        let bytes = std::fs::read(path.path()).unwrap();
        let v = dump_sqlite_bytes(&bytes, 0).unwrap();
        let items = v.get("items").and_then(|a| a.as_array()).unwrap();
        assert_eq!(items[0]["name"], "hello");
        assert_eq!(items[0]["flag"], 1);
    }

    #[test]
    fn query_select_returns_rows() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER, label TEXT);
             INSERT INTO t VALUES (1, 'a');",
        )
        .unwrap();
        let bytes = std::fs::read(path.path()).unwrap();
        let rows = query_sqlite_select(&bytes, "SELECT id, label FROM t").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["label"], "a");
    }
}
