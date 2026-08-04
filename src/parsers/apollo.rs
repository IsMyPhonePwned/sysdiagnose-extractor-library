//! APOLLO-style SQLite queries from bundled upstream module definitions
//! ([`sysdiagnose` `apollo_modules`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/tree/main/src/sysdiagnose/utils/apollo_modules)),
//! matching [`Apollo.parse_db`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/apollo.py)
//! behaviour for `os_version='yolo'` (all `SQL Query` sections run).

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::OnceLock;

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_events::{naive_utc, saf_event_dict, wrap_jsonl};

const APOLLO_MAX_ROWS_PER_QUERY: usize = 100_000;

#[derive(Clone)]
struct ModuleQuery {
    query_name: String,
    activity: String,
    key_timestamp: String,
    sql: String,
    source_file: String,
}

struct ApolloRegistry {
    by_db: HashMap<String, Vec<ModuleQuery>>,
}

impl ApolloRegistry {
    fn global() -> &'static Self {
        static REG: OnceLock<ApolloRegistry> = OnceLock::new();
        REG.get_or_init(|| {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("apollo_modules");
            let by_db = load_apollo_modules_dir(&dir);
            if by_db.is_empty() {
                tracing::warn!(
                    path = %dir.display(),
                    "apollo_modules directory missing or empty; accessibility_tcc and powerlogs Apollo queries will return no events"
                );
            }
            ApolloRegistry { by_db }
        })
    }

    fn queries_for(&self, db_type: &str) -> &[ModuleQuery] {
        self.by_db.get(db_type).map(|v| v.as_slice()).unwrap_or(&[])
    }

    fn all_db_types(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.by_db.keys().cloned().collect();
        keys.sort();
        keys
    }

    fn module_count(&self) -> usize {
        self.by_db.values().map(|v| v.len()).sum()
    }
}

fn load_apollo_modules_dir(dir: &Path) -> HashMap<String, Vec<ModuleQuery>> {
    let mut map: HashMap<String, Vec<ModuleQuery>> = HashMap::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return map;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(content) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Some(pm) = parse_apollo_module_file(name, &content) else {
            continue;
        };
        for sql in pm.sql_blocks {
            for db in &pm.databases {
                map.entry(db.clone()).or_default().push(ModuleQuery {
                    query_name: pm.query_name.clone(),
                    activity: pm.activity.clone(),
                    key_timestamp: pm.key_timestamp.to_ascii_lowercase(),
                    sql: sql.clone(),
                    source_file: pm.source_file.clone(),
                });
            }
        }
    }
    for v in map.values_mut() {
        v.sort_by(|a, b| {
            a.source_file
                .cmp(&b.source_file)
                .then_with(|| a.query_name.cmp(&b.query_name))
                .then_with(|| a.sql.cmp(&b.sql))
        });
    }
    map
}

struct ParsedModule {
    databases: Vec<String>,
    query_name: String,
    activity: String,
    key_timestamp: String,
    sql_blocks: Vec<String>,
    source_file: String,
}

fn split_ini_sections(content: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = content.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '[' {
            i += 1;
            continue;
        }
        let Some(rel_end) = chars[i + 1..].iter().position(|&c| c == ']') else {
            break;
        };
        let end = i + 1 + rel_end;
        let name: String = chars[i + 1..end].iter().collect();
        i = end + 1;
        while i < chars.len() && matches!(chars[i], '\r' | '\n') {
            i += 1;
        }
        let start = i;
        while i < chars.len() && chars[i] != '[' {
            i += 1;
        }
        let body: String = chars[start..i].iter().collect();
        out.push((name, body));
    }
    out
}

fn parse_kv_section(body: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            m.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    m
}

fn extract_query_sql(section_body: &str) -> Option<String> {
    let lines: Vec<&str> = section_body.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let tl = lines[i].trim_start();
        let lower = tl.to_ascii_lowercase();
        if lower.starts_with("query") && tl.contains('=') {
            let pos = tl.find('=')?;
            let after = tl[pos + 1..].trim();
            let mut sql = String::new();
            if !after.is_empty() {
                sql.push_str(after);
                sql.push('\n');
            }
            for j in (i + 1)..lines.len() {
                sql.push_str(lines[j]);
                sql.push('\n');
            }
            let s = sql.trim().to_string();
            return if s.is_empty() { None } else { Some(s) };
        }
        i += 1;
    }
    None
}

fn parse_apollo_module_file(source_file: &str, content: &str) -> Option<ParsedModule> {
    let sections = split_ini_sections(content);
    let mut databases: Option<Vec<String>> = None;
    let mut q_meta: Option<(String, String, String)> = None;
    let mut sql_blocks: Vec<String> = Vec::new();

    for (sec, body) in sections {
        let sec_trim = sec.trim();
        if sec_trim.eq_ignore_ascii_case("Database Metadata") {
            let m = parse_kv_section(&body);
            let d = m.get("DATABASE")?.clone();
            databases = Some(
                d.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            );
        } else if sec_trim.eq_ignore_ascii_case("Query Metadata") {
            let m = parse_kv_section(&body);
            let qn = m.get("QUERY_NAME")?.clone();
            let act = m.get("ACTIVITY")?.clone();
            let kts = m.get("KEY_TIMESTAMP")?.clone();
            q_meta = Some((qn, act, kts));
        } else if sec_trim.contains("SQL Query") {
            if let Some(sql) = extract_query_sql(&body) {
                sql_blocks.push(sql);
            }
        }
    }

    let databases = databases?;
    let (query_name, activity, key_timestamp) = q_meta?;
    if sql_blocks.is_empty() {
        return None;
    }
    Some(ParsedModule {
        databases,
        query_name,
        activity,
        key_timestamp,
        sql_blocks,
        source_file: source_file.to_string(),
    })
}

fn json_value_compact(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

fn apollo_message(activity: &str, headers: &[String], values: &[Value], key_ts: &str) -> String {
    let parts: Vec<String> = headers
        .iter()
        .zip(values.iter())
        .filter(|(k, _)| {
            let kl = k.to_ascii_lowercase();
            // Skip the timestamp column and internal table/row ids — but keep
            // inventory fields like "bundle id" / "app build version".
            *k != key_ts
                && !kl.contains("timestamp")
                && kl != "id"
                && !kl.ends_with(" table id")
                && !kl.ends_with("_table_id")
        })
        .map(|(k, v)| format!("{}={}", k, json_value_compact(v)))
        .collect();
    format!("{}: {}", activity, parts.join(", "))
}

fn normalize_ts_key(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn timestamp_value_from_row<'a>(item: &'a Map<String, Value>, key_ts: &str) -> Option<&'a Value> {
    let want = normalize_ts_key(key_ts);
    if let Some(v) = item.get(key_ts) {
        return Some(v);
    }
    for (k, v) in item {
        if normalize_ts_key(k) == want {
            return Some(v);
        }
    }
    None
}

/// Parse APOLLO / SQLite timestamp cells (strings, Unix epoch integers, floats).
pub fn parse_apollo_timestamp_value(v: &Value) -> Option<DateTime<FixedOffset>> {
    match v {
        Value::String(s) => parse_apollo_timestamp_str(s),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return unix_epoch_to_datetime(i);
            }
            if let Some(f) = n.as_f64() {
                return unix_epoch_to_datetime(f.floor() as i64);
            }
            None
        }
        _ => None,
    }
}

fn unix_epoch_to_datetime(secs: i64) -> Option<DateTime<FixedOffset>> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.with_timezone(&FixedOffset::east_opt(0).unwrap()))
}

/// Parse APOLLO / SQLite timestamp strings.
pub(crate) fn parse_apollo_timestamp_str(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(secs) = s.parse::<i64>() {
        if let Some(dt) = unix_epoch_to_datetime(secs) {
            return Some(dt);
        }
    }
    if let Ok(secs) = s.parse::<f64>() {
        if secs.is_finite() {
            return unix_epoch_to_datetime(secs.floor() as i64);
        }
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive_utc(dt));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(naive_utc(dt));
    }
    // CPython datetime.fromisoformat accepts "YYYY-MM-DD HH:MM:SS" and "YYYY-MM-DDTHH:MM:SS".
    let isoish = s.replace(' ', "T");
    if isoish != s {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&format!("{isoish}+00:00")) {
            return Some(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()));
        }
        if let Ok(dt) = NaiveDateTime::parse_from_str(&isoish, "%Y-%m-%dT%H:%M:%S") {
            return Some(naive_utc(dt));
        }
        if let Ok(dt) = NaiveDateTime::parse_from_str(&isoish, "%Y-%m-%dT%H:%M:%S%.f") {
            return Some(naive_utc(dt));
        }
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(naive_utc(dt));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(naive_utc(dt));
    }
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %z") {
        return Some(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()));
    }
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f %z") {
        return Some(dt.with_timezone(&FixedOffset::east_opt(0).unwrap()));
    }
  None
}

#[cfg(not(target_arch = "wasm32"))]
fn rusqlite_value_to_json(v: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => json!(format!("<{} bytes binary>", b.len())),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn run_apollo_on_db_bytes(
    db_path: &str,
    bytes: &[u8],
    _db_type: &str,
    saf_module: &str,
    queries: &[ModuleQuery],
) -> Result<Vec<Value>, Box<dyn Error + Send + Sync>> {
    use std::io::Write;

    use rusqlite::Connection;

    let mut events = Vec::new();
    if queries.is_empty() {
        return Ok(events);
    }

    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(bytes)?;
    let conn = Connection::open(tmp.path())?;

    for mq in queries {
        let mut stmt = match conn.prepare(&mq.sql) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(
                    apollo_module = %mq.query_name,
                    file = %mq.source_file,
                    error = %e,
                    "Apollo SQL prepare failed (schema mismatch is normal)"
                );
                continue;
            }
        };
        let ncols = stmt.column_count();
        let headers: Vec<String> = (0..ncols)
            .map(|i| stmt.column_name(i).unwrap_or("").to_ascii_lowercase())
            .collect();
        let mut rows = match stmt.query([]) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    apollo_module = %mq.query_name,
                    error = %e,
                    "Apollo SQL execute failed"
                );
                continue;
            }
        };

        let mut row_count = 0usize;
        while let Some(row) = rows.next()? {
            if row_count >= APOLLO_MAX_ROWS_PER_QUERY {
                tracing::warn!(
                    apollo_module = %mq.query_name,
                    limit = APOLLO_MAX_ROWS_PER_QUERY,
                    "Apollo query row cap reached"
                );
                break;
            }
            row_count += 1;

            let mut values: Vec<Value> = Vec::with_capacity(ncols);
            let mut item = Map::new();
            for i in 0..ncols {
                let val = rusqlite_value_to_json(row.get_ref(i)?);
                values.push(val.clone());
                if let Some(k) = headers.get(i) {
                    item.insert(k.clone(), val);
                }
            }

            let ts_val = timestamp_value_from_row(&item, mq.key_timestamp.as_str());
            let Some(dt) = ts_val.and_then(parse_apollo_timestamp_value) else {
                tracing::debug!(
                    apollo_module = %mq.query_name,
                    ts = ?ts_val,
                    key = %mq.key_timestamp,
                    "Apollo timestamp parse failed; skipping row"
                );
                continue;
            };

            item.insert("apollo_module".into(), json!(mq.query_name));
            item.insert("source_db".into(), json!(db_path));

            let message =
                apollo_message(&mq.activity, &headers, &values, mq.key_timestamp.as_str());
            let ev = saf_event_dict(saf_module, dt, &mq.activity, &message, Value::Object(item));
            events.push(ev);
        }
    }

    Ok(events)
}

/// Run bundled APOLLO modules for `db_type` on every archive file matching `path_patterns`.
/// Returns [`wrap_jsonl`] output (`parser`, `format`, `events`) aligned with other jsonl parsers.
#[cfg(not(target_arch = "wasm32"))]
pub fn parse_apollo_archives(
    archive: &SysdiagnoseArchive,
    parser_id: &'static str,
    path_patterns: &[&str],
    db_type: &'static str,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    use globset::Error as GlobError;

    let reg = ApolloRegistry::global();
    let queries = reg.queries_for(db_type);
    let files =
        matching_files_patterns(archive, path_patterns).map_err(|e: GlobError| e.to_string())?;
    let mut all_events = Vec::new();
    for (p, b) in files {
        match run_apollo_on_db_bytes(p, b, db_type, parser_id, queries) {
            Ok(mut evs) => all_events.append(&mut evs),
            Err(e) => {
                tracing::warn!(path = %p, error = %e, "Apollo DB open failed");
            }
        }
    }
    Ok(wrap_jsonl(parser_id, all_events))
}

/// Whether an archive path can host APOLLO SQLite queries for `db_type`.
pub fn archive_path_matches_db_type(path: &str, db_type: &str) -> bool {
    use std::path::Path;
    let path_lc = path.to_ascii_lowercase();
    if path.ends_with(db_type) {
        if db_type == "db" {
            return path_lc.contains("notification")
                || path_lc.contains("usernotifications")
                || path_lc.contains("/db2/");
        }
        return true;
    }
    if Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        == Some(db_type)
    {
        if db_type == "db" {
            return path_lc.contains("notification")
                || path_lc.contains("usernotifications")
                || path_lc.contains("/db2/");
        }
        return true;
    }
    false
}

fn looks_like_apollo_db_file(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".db")
        || p.ends_with(".sqlite")
        || p.ends_with(".sqlitedb")
        || p.ends_with(".plsql")
        || p.ends_with(".storedata")
        || p.contains("execpolicy")
        || p.contains("kextpolicy")
}

/// Run every bundled APOLLO module against matching SQLite files discovered in the archive.
#[cfg(not(target_arch = "wasm32"))]
pub fn parse_apollo_all_archives(
    archive: &SysdiagnoseArchive,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    use std::collections::HashSet;

    let reg = ApolloRegistry::global();
    let db_types = reg.all_db_types();
    let mut all_events = Vec::new();
    let mut matched = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (path, bytes) in archive.iter_files() {
        if !looks_like_apollo_db_file(path) {
            continue;
        }
        for db_type in &db_types {
            if !archive_path_matches_db_type(path, db_type) {
                continue;
            }
            if !seen.insert((path.to_string(), db_type.clone())) {
                continue;
            }
            let queries = reg.queries_for(db_type);
            if queries.is_empty() {
                continue;
            }
            match run_apollo_on_db_bytes(path, bytes, db_type, "apollo_all", queries) {
                Ok(evs) => {
                    matched.push(json!({
                        "path": path,
                        "db_type": db_type,
                        "event_count": evs.len(),
                    }));
                    all_events.extend(evs);
                }
                Err(e) => {
                    tracing::warn!(path = %path, db_type = %db_type, error = %e, "Apollo DB open failed");
                }
            }
        }
    }

    let mut out = wrap_jsonl("apollo_all", all_events);
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "meta".into(),
            json!({
                "databases_matched": matched,
                "db_types_in_registry": db_types.len(),
                "apollo_query_count": reg.module_count(),
            }),
        );
    }
    Ok(out)
}

#[cfg(target_arch = "wasm32")]
pub fn parse_apollo_all_archives(
    archive: &SysdiagnoseArchive,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let _ = archive;
    Ok(wrap_jsonl("apollo_all", vec![]))
}

#[cfg(target_arch = "wasm32")]
pub fn parse_apollo_archives(
    _archive: &SysdiagnoseArchive,
    parser_id: &'static str,
    _path_patterns: &[&str],
    _db_type: &'static str,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    Ok(wrap_jsonl(parser_id, vec![]))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    use rusqlite::Connection;

    #[test]
    fn apollo_timestamp_unix_integer_and_fuzzy_column() {
        let mut item = Map::new();
        item.insert("last_modified".into(), json!(1_700_000_000_i64));
        item.insert("service".into(), json!("kTCCServiceCamera"));
        let ts = timestamp_value_from_row(&item, "last modified")
            .and_then(parse_apollo_timestamp_value)
            .expect("unix int via fuzzy key");
        assert_eq!(ts.timestamp(), 1_700_000_000);
    }

    #[test]
    fn apollo_timestamp_iso_and_sqlite_datetime_strings() {
        let s = parse_apollo_timestamp_str("2023-11-14 22:13:20").unwrap();
        assert_eq!(s.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-11-14 22:13:20");
        let t = parse_apollo_timestamp_str("2023-11-14T22:13:20").unwrap();
        assert_eq!(t.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-11-14 22:13:20");
        let r = parse_apollo_timestamp_str("2023-11-14T22:13:20.123456+00:00").unwrap();
        assert_eq!(r.timestamp(), 1_700_000_000);
    }

    #[test]
    fn apollo_registry_loads_bundled_modules() {
        let reg = ApolloRegistry::global();
        assert!(
            reg.module_count() >= 200,
            "expected 200+ APOLLO query blocks under apollo_modules/"
        );
        assert!(reg.queries_for("TCC.db").len() >= 1);
        assert!(reg.queries_for("knowledgeC.db").len() >= 50);
    }

    #[test]
    fn archive_path_matches_db_type_heuristics() {
        assert!(archive_path_matches_db_type(
            "logs/Accessibility/TCC.db",
            "TCC.db"
        ));
        assert!(archive_path_matches_db_type(
            "logs/powerlogs/CurrentPowerlog.PLSQL",
            "CurrentPowerlog.PLSQL"
        ));
        assert!(!archive_path_matches_db_type("logs/foo/db", "db"));
        assert!(archive_path_matches_db_type(
            "logs/UserNotifications/db2/db",
            "db"
        ));
    }

    #[test]
    fn apollo_tcc_minimal_db_emits_event() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(tmp.path()).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE access (
                    last_modified INTEGER,
                    service TEXT,
                    client TEXT,
                    auth_value INTEGER,
                    auth_reason INTEGER,
                    client_type INTEGER,
                    indirect_object_identifier TEXT
                );
                INSERT INTO access VALUES (
                    1700000000,
                    'kTCCServiceCamera',
                    'com.example.tccapp',
                    2,
                    0,
                    0,
                    ''
                );
            "#,
            )
            .unwrap();
        }
        let bytes = std::fs::read(tmp.path()).unwrap();
        let reg = ApolloRegistry::global();
        let q = reg.queries_for("TCC.db");
        assert!(
            !q.is_empty(),
            "TCC.db Apollo modules should be present under apollo_modules/"
        );
        let events = run_apollo_on_db_bytes(
            "logs/Accessibility/TCC.db",
            &bytes,
            "TCC.db",
            "accessibility_tcc",
            q,
        )
        .unwrap();
        assert!(!events.is_empty(), "{events:?}");
        let data = events[0]["data"].as_object().unwrap();
        assert_eq!(data["client"], "com.example.tccapp");
        assert_eq!(data["service"], "kTCCServiceCamera");
        assert_eq!(data["apollo_module"], "tcc_db");
    }
}
