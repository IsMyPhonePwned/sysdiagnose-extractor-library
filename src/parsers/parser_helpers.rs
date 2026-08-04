//! Shared extraction helpers for sysdiagnose parsers.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::{Cursor, Read};

use flate2::read::GzDecoder;
use globset::Error as GlobError;
use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::{compile_globs, matching_files, matching_files_patterns};
use crate::sqlite_dump::dump_sqlite_bytes;
use crate::tab_hierarchy::parse_tab_hierarchy_text;

pub const MAX_UTF8_FILE: usize = 8 * 1024 * 1024;
pub const MAX_PLIST_EACH: usize = 4 * 1024 * 1024;
pub const SQLITE_MAX_ROWS_PER_TABLE: usize = 25_000;

/// Path → UTF-8 string map (used by some structured-extract parsers; others use [`matching_utf8_files`](crate::parsers::parser_events::matching_utf8_files) directly).
#[allow(dead_code)]
pub fn utf8_map(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let mut m = Map::new();
    for (p, b) in files {
        if b.len() > MAX_UTF8_FILE {
            m.insert(
                p.to_string(),
                json!({ "skipped_oversized": true, "size": b.len() }),
            );
            continue;
        }
        m.insert(
            p.to_string(),
            json!(String::from_utf8_lossy(b).into_owned()),
        );
    }
    Ok(Value::Object(m))
}

pub fn plist_map_patterns(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    plist_map_files(files)
}

fn plist_map_files(files: Vec<(&str, &[u8])>) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let mut m = Map::new();
    for (p, b) in files {
        if b.len() > MAX_PLIST_EACH {
            m.insert(
                p.to_string(),
                json!({ "error": "oversized plist", "size": b.len() }),
            );
            continue;
        }
        match plist::from_reader::<_, plist::Value>(std::io::Cursor::new(b)) {
            Ok(v) => match serde_json::to_value(&v) {
                Ok(j) => {
                    m.insert(p.to_string(), j);
                }
                Err(e) => {
                    m.insert(p.to_string(), json!({ "error": e.to_string() }));
                }
            },
            Err(e) => {
                m.insert(p.to_string(), json!({ "error": e.to_string() }));
            }
        }
    }
    Ok(Value::Object(m))
}

/// Recursive `**/*.plist` export with caps, per-file `{}` on failure (upstream `plists.py`).
pub fn plists_recursive_with_caps(
    archive: &SysdiagnoseArchive,
    caps: crate::parsers::plists_config::PlistsCaps,
) -> Value {
    let set = match compile_globs(&["**/*.plist"]) {
        Ok(s) => s,
        Err(e) => return json!({ "files": {}, "meta": { "error": e.to_string() } }),
    };
    let mut files: Vec<_> = matching_files(archive, &set);
    files.sort_by_key(|(p, _)| *p);
    let total_matched = files.len();
    let mut truncated_paths: Vec<String> = Vec::new();
    if caps.max_files > 0 && files.len() > caps.max_files {
        for (p, _) in &files[caps.max_files..] {
            truncated_paths.push((*p).to_string());
        }
        files.truncate(caps.max_files);
    }

    let mut out_files = Map::new();
    let mut parse_failures: Vec<String> = Vec::new();
    let mut skipped_oversized: Vec<String> = Vec::new();

    for (p, b) in files {
        if caps.max_each_bytes > 0 && b.len() > caps.max_each_bytes {
            skipped_oversized.push(p.to_string());
            out_files.insert(p.to_string(), json!({}));
            continue;
        }
        match plist::from_reader::<_, plist::Value>(std::io::Cursor::new(b)) {
            Ok(v) => match serde_json::to_value(&v) {
                Ok(j) => {
                    out_files.insert(p.to_string(), j);
                }
                Err(_) => {
                    parse_failures.push(p.to_string());
                    out_files.insert(p.to_string(), json!({}));
                }
            },
            Err(_) => {
                parse_failures.push(p.to_string());
                out_files.insert(p.to_string(), json!({}));
            }
        }
    }

    json!({
        "files": out_files,
        "meta": {
            "max_files": caps.max_files,
            "max_each_bytes": caps.max_each_bytes,
            "total_matched": total_matched,
            "parsed_count": out_files.len(),
            "truncated_file_count": truncated_paths.len(),
            "truncated_paths": truncated_paths,
            "parse_failures": parse_failures,
            "skipped_oversized": skipped_oversized,
        }
    })
}

pub fn sqlite_map(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    sqlite_map_with_limit(archive, patterns, SQLITE_MAX_ROWS_PER_TABLE)
}

/// Like [`sqlite_map`] but `max_rows_per_table == 0` means no row limit (upstream `sqlite2struct`).
pub fn sqlite_map_with_limit(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
    max_rows_per_table: usize,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let mut m = Map::new();
    for (p, b) in files {
        match dump_sqlite_bytes(b, max_rows_per_table) {
            Ok(v) => {
                m.insert(p.to_string(), v);
            }
            Err(e) => {
                m.insert(p.to_string(), json!({ "error": e.to_string() }));
            }
        }
    }
    Ok(Value::Object(m))
}

/// First matching SQLite file → `{ table: [rows] }` (upstream `itunesstore.execute()` shape).
pub fn sqlite_first_db_tables(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let Some((path, b)) = files.first() else {
        return Ok(json!({}));
    };
    let tables = dump_sqlite_bytes(b, 0)?;
    Ok(json!({
        "source_path": path,
        "data": tables,
    }))
}

pub fn prefix_inventory(archive: &SysdiagnoseArchive, prefix: &str) -> Value {
    prefix_inventory_capped(archive, prefix, logarchive_inventory_max_paths())
}

fn logarchive_inventory_max_paths() -> usize {
    std::env::var("SYSDIAGNOSE_LOGARCHIVE_INVENTORY_MAX_PATHS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
}

/// Path listing under `prefix` with rollup stats; `paths` capped (largest files first).
pub fn prefix_inventory_capped(
    archive: &SysdiagnoseArchive,
    prefix: &str,
    max_paths: usize,
) -> Value {
    let mut entries: Vec<(String, usize)> = archive
        .iter_files()
        .filter(|(p, _)| p.starts_with(prefix))
        .map(|(p, b)| (p.to_string(), b.len()))
        .collect();

    #[cfg(not(target_arch = "wasm32"))]
    if prefix.starts_with("system_logs.logarchive") || "system_logs.logarchive/".starts_with(prefix)
    {
        for (p, size) in archive.logarchive_spilled_entries() {
            if p.starts_with(prefix) {
                entries.push((p.clone(), *size as usize));
            }
        }
    }

    let file_count = entries.len();
    let total_bytes: usize = entries.iter().map(|(_, s)| s).sum();

    let mut by_subdir: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (p, size) in &entries {
        let rel = p.strip_prefix(prefix).unwrap_or(p.as_str());
        let seg = rel.split('/').next().unwrap_or("").to_string();
        let key = if seg.is_empty() { ".".to_string() } else { seg };
        let e = by_subdir.entry(key).or_insert((0, 0));
        e.0 += 1;
        e.1 += size;
    }

    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let paths_truncated = file_count > max_paths;
    let paths: Vec<Value> = entries
        .iter()
        .take(max_paths)
        .map(|(p, size)| json!({ "path": p, "size": size }))
        .collect();

    let by_subdir_json: Map<String, Value> = by_subdir
        .into_iter()
        .map(|(k, (count, bytes))| (k, json!({ "count": count, "bytes": bytes })))
        .collect();

    json!({
        "file_count": file_count,
        "total_bytes": total_bytes,
        "by_subdir": by_subdir_json,
        "paths": paths,
        "paths_truncated": paths_truncated,
        "paths_cap": max_paths,
    })
}

#[allow(dead_code)]
pub fn gzip_utf8_map(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let mut m = Map::new();
    for (p, b) in files {
        let mut dec = GzDecoder::new(Cursor::new(b));
        let mut out = Vec::new();
        if dec.read_to_end(&mut out).is_err() {
            m.insert(p.to_string(), json!({ "error": "gzip_decode_failed" }));
            continue;
        }
        if out.len() > MAX_UTF8_FILE {
            m.insert(
                p.to_string(),
                json!({ "skipped_oversized_decompressed": true, "size": out.len() }),
            );
            continue;
        }
        m.insert(
            p.to_string(),
            json!(String::from_utf8_lossy(&out).into_owned()),
        );
    }
    Ok(Value::Object(m))
}

#[allow(dead_code)]
pub fn csv_map(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let mut m = Map::new();
    for (p, b) in files {
        if b.len() > MAX_UTF8_FILE {
            m.insert(p.to_string(), json!({ "skipped_oversized": true }));
            continue;
        }
        let text = String::from_utf8_lossy(b);
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(text.as_bytes());
        let headers = rdr
            .headers()
            .ok()
            .map(|h| h.iter().map(String::from).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut rows = Vec::new();
        for rec in rdr.records() {
            let rec = match rec {
                Ok(r) => r,
                Err(e) => {
                    rows.push(json!({ "error": e.to_string() }));
                    continue;
                }
            };
            let mut obj = Map::new();
            for (i, h) in headers.iter().enumerate() {
                obj.insert(h.clone(), json!(rec.get(i).unwrap_or("").to_string()));
            }
            rows.push(Value::Object(obj));
        }
        m.insert(p.to_string(), json!(rows));
    }
    Ok(Value::Object(m))
}

#[allow(dead_code)]
pub fn jsonl_bundle(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let mut m = Map::new();
    for (p, b) in files {
        if b.len() > MAX_UTF8_FILE {
            m.insert(p.to_string(), json!({ "skipped_oversized": true }));
            continue;
        }
        let text = String::from_utf8_lossy(b);
        let mut lines = Vec::new();
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(t) {
                Ok(v) => lines.push(v),
                Err(e) => lines.push(json!({ "parse_error": e.to_string(), "line": t })),
            }
        }
        m.insert(p.to_string(), json!(lines));
    }
    Ok(Value::Object(m))
}

pub fn json_whole_first(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let Some((p, b)) = files.first() else {
        return Ok(json!({ "error": "no_matching_file" }));
    };
    if b.len() > MAX_UTF8_FILE {
        return Ok(json!({ "error": "oversized", "path": p, "size": b.len() }));
    }
    let text = String::from_utf8_lossy(b);
    let trimmed = text.trim();
    // Empty / whitespace-only transparency.log (and similar) is common — soft-fail.
    if trimmed.is_empty() {
        return Ok(json!({ "error": "empty_file", "path": p }));
    }
    match serde_json::from_str(trimmed) {
        Ok(v) => Ok(v),
        Err(e) => Ok(json!({
            "error": "parse_error",
            "path": p,
            "detail": e.to_string(),
        })),
    }
}

pub fn remotectl_tab(archive: &SysdiagnoseArchive) -> Value {
    let patterns = ["remotectl_dumpstate.txt"];
    let Ok(files) = matching_files_patterns(archive, &patterns) else {
        return json!({ "error": "glob_compile" });
    };
    let Some((p, b)) = files.first() else {
        return json!({ "error": "No remotectl_dumpstate.txt file present" });
    };
    if b.len() > MAX_UTF8_FILE {
        return json!({ "error": "oversized", "path": p });
    }
    let text = String::from_utf8_lossy(b);
    parse_tab_hierarchy_text(&text)
}

pub fn file_stem_key(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.rsplit_once('.')
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| base.to_string())
}

pub fn parse_ioreg_file(archive: &SysdiagnoseArchive, path: &str) -> Value {
    let Some(b) = archive.get(path) else {
        return json!({});
    };
    if b.len() > MAX_UTF8_FILE {
        return json!({ "error": "oversized", "path": path, "size": b.len() });
    }
    crate::parsers::ioreg::IORegStructParser::parse_bytes(b)
}

pub fn ioreg_parse_result(archive: &SysdiagnoseArchive, path: &str, parser_id: &str) -> Value {
    if archive.get(path).is_none() {
        return json!({});
    }
    json!({
        "parser": parser_id,
        "tree": parse_ioreg_file(archive, path),
    })
}

pub fn brctl_parsed(archive: &SysdiagnoseArchive) -> Value {
    let list = archive.get("brctl/brctl-container-list.txt");
    let dump = archive.get("brctl/brctl-dump.txt");
    let (Some(list_b), Some(dump_b)) = (list, dump) else {
        return json!({});
    };
    if list_b.len() > MAX_UTF8_FILE || dump_b.len() > MAX_UTF8_FILE {
        return json!({ "error": "oversized brctl file" });
    }
    let list_s = String::from_utf8_lossy(list_b);
    let dump_s = String::from_utf8_lossy(dump_b);
    crate::parsers::parser_events::parse_brctl_folder(&list_s, &dump_s)
}

pub fn wifinetworks_bundle(
    archive: &SysdiagnoseArchive,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let pl = plist_map_patterns(archive, &["WiFi/*.plist", "**/WiFi/*.plist"])?;
    let mut root = Map::new();
    if let Value::Object(m) = pl {
        for (path, val) in m {
            root.insert(file_stem_key(&path), val);
        }
    }
    let jfiles = matching_files_patterns(
        archive,
        &[
            "WiFi/com.apple.wifi.recent-networks.json",
            "**/WiFi/com.apple.wifi.recent-networks.json",
        ],
    )?;
    if let Some((p, b)) = jfiles.first() {
        if b.len() <= MAX_UTF8_FILE {
            let text = String::from_utf8_lossy(b);
            root.insert(
                file_stem_key(p),
                serde_json::from_str(&text).unwrap_or_else(|e| json!({ "error": e.to_string() })),
            );
        }
    }
    Ok(Value::Object(root))
}

#[allow(dead_code)]
pub fn transparency_jsonl(archive: &SysdiagnoseArchive) -> Value {
    let patterns = ["transparency.log"];
    let Ok(files) = matching_files_patterns(archive, &patterns) else {
        return json!({ "events": [] });
    };
    let Some((_, b)) = files.first() else {
        return json!({ "events": [] });
    };
    if b.len() > MAX_UTF8_FILE {
        return json!({ "error": "oversized" });
    }
    let text = String::from_utf8_lossy(b);
    let mut events = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            events.push(v);
        }
    }
    json!({ "events": events })
}
