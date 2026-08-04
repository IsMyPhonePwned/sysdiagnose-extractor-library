//! Map sysdiagnose parser JSON into [`sigma_zero::models::LogEntry`] values for Sigma Zero rules.

use serde_json::{json, Value};
use sigma_zero::models::LogEntry;
use std::error::Error;
use tracing::{debug, info, warn};

use crate::parsers::ParserType;

const MAX_ENTRIES_PER_PARSER: usize = 15_000;
const MAX_TEXT_SNIPPET: usize = 16_384;
const MAX_SINGLE_OBJECT_KEYS: usize = 256;

fn json_to_log_entry(value: Value) -> Result<LogEntry, Box<dyn Error + Send + Sync>> {
    let json_str = serde_json::to_string(&value)?;
    Ok(serde_json::from_str(&json_str)?)
}

fn append_context(obj: &mut serde_json::Map<String, Value>, parser: &str, output: &Value) {
    obj.entry("sysdiagnose_parser".to_string())
        .or_insert(json!(parser));
    if let Some(p) = output.get("parser") {
        obj.entry("parser_module".to_string()).or_insert(p.clone());
    }
    if let Some(s) = output.get("source") {
        obj.entry("parser_source".to_string()).or_insert(s.clone());
    }
}

/// Extract Sigma log entries from successful parser results (same role as
/// `bugreport_extractor_library::detection::sigma::extract_all_log_entries`).
pub fn extract_all_log_entries(
    results: &[(
        ParserType,
        Result<Value, Box<dyn Error + Send + Sync>>,
        std::time::Duration,
    )],
) -> Vec<(ParserType, Vec<LogEntry>)> {
    let mut all_entries = Vec::new();

    for (parser_type, result, _duration) in results {
        match result {
            Ok(json_output) => {
                debug!(
                    "Sigma: extracting log entries from {} parser",
                    parser_type.as_str()
                );
                if let Some(entries) = extract_entries_for_parser(parser_type, json_output) {
                    if entries.is_empty() {
                        debug!("{} parser: no Sigma entries", parser_type.as_str());
                    } else {
                        info!(
                            "{} parser: extracted {} log entries for Sigma",
                            parser_type.as_str(),
                            entries.len()
                        );
                        all_entries.push((*parser_type, entries));
                    }
                } else {
                    debug!(
                        "{} parser: no Sigma-compatible extraction",
                        parser_type.as_str()
                    );
                }
            }
            Err(e) => {
                warn!(
                    "{} parser failed, skipping Sigma extraction: {}",
                    parser_type.as_str(),
                    e
                );
            }
        }
    }

    let total: usize = all_entries.iter().map(|(_, e)| e.len()).sum();
    info!(
        "Sigma conversion: {} parsers, {} total log entries",
        all_entries.len(),
        total
    );

    all_entries
}

fn extract_entries_for_parser(pt: &ParserType, output: &Value) -> Option<Vec<LogEntry>> {
    let parser = pt.as_str();
    let mut out = Vec::new();
    let mut budget = MAX_ENTRIES_PER_PARSER;

    extract_named_object_arrays(parser, output, output, &mut budget, &mut out);
    if !out.is_empty() {
        return Some(out);
    }

    let inner = output
        .get("files")
        .filter(|v| v.is_object())
        .unwrap_or(output);
    extract_path_value_map(parser, inner, output, &mut budget, &mut out);
    extract_sqlite_shape(parser, inner, output, &mut budget, &mut out);
    if !out.is_empty() {
        return Some(out);
    }

    if let Some(e) = try_whole_output_as_entry(parser, output) {
        out.push(e);
        return Some(out);
    }

    None
}

fn extract_named_object_arrays(
    parser: &str,
    template: &Value,
    output: &Value,
    budget: &mut usize,
    out: &mut Vec<LogEntry>,
) {
    for key in ["rows", "events", "lines"] {
        if *budget == 0 {
            return;
        }
        let Some(arr) = output.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for item in arr {
            if *budget == 0 {
                return;
            }
            if let Some(obj) = item.as_object() {
                let mut j = Value::Object(obj.clone());
                if let Some(m) = j.as_object_mut() {
                    append_context(m, parser, template);
                }
                if let Ok(e) = json_to_log_entry(j) {
                    out.push(e);
                    *budget -= 1;
                }
            }
        }
    }
}

fn key_looks_like_path(key: &str) -> bool {
    key.contains('/')
        || key.ends_with(".plist")
        || key.ends_with(".txt")
        || key.ends_with(".log")
        || key.ends_with(".json")
        || key.ends_with(".jsonl")
        || key.ends_with(".csv")
}

fn extract_path_value_map(
    parser: &str,
    inner: &Value,
    template: &Value,
    budget: &mut usize,
    out: &mut Vec<LogEntry>,
) {
    let Some(obj) = inner.as_object() else {
        return;
    };

    let path_like_keys = obj.keys().filter(|k| {
        !matches!(
            k.as_str(),
            "parser" | "error" | "ok" | "paths" | "note" | "inventory" | "files" | "tree"
        ) && key_looks_like_path(k)
    });
    let path_like = path_like_keys.count();
    if path_like == 0 && obj.len() > 8 {
        return;
    }

    for (path_key, val) in obj {
        if *budget == 0 {
            return;
        }
        if matches!(
            path_key.as_str(),
            "parser" | "error" | "paths" | "note" | "inventory" | "files" | "tree" | "data"
        ) {
            continue;
        }
        if val.is_object() {
            if val.as_object().map(|o| o.len()) == Some(1) && val.get("error").is_some() {
                continue;
            }
            if let Some(row_arr) = val.get("rows").and_then(|v| v.as_array()) {
                for item in row_arr {
                    if *budget == 0 {
                        return;
                    }
                    if let Some(o) = item.as_object() {
                        let mut j = Value::Object(o.clone());
                        if let Some(m) = j.as_object_mut() {
                            append_context(m, parser, template);
                            m.insert("source_path".to_string(), json!(path_key));
                        }
                        if let Ok(e) = json_to_log_entry(j) {
                            out.push(e);
                            *budget -= 1;
                        }
                    }
                }
                continue;
            }
            if is_sqlite_tables_object(val) {
                continue;
            }
            let mut j = val.clone();
            if let Some(m) = j.as_object_mut() {
                append_context(m, parser, template);
                m.insert("source_path".to_string(), json!(path_key));
                m.entry("event_type".to_string())
                    .or_insert(json!("structured_file"));
            }
            if let Ok(e) = json_to_log_entry(j) {
                out.push(e);
                *budget -= 1;
            }
            continue;
        }
        if let Some(s) = val.as_str() {
            let snippet: String = s.chars().take(MAX_TEXT_SNIPPET).collect();
            let j = json!({
                "event_type": "text_snippet",
                "source_path": path_key,
                "sysdiagnose_parser": parser,
                "content": snippet,
            });
            if let Ok(e) = json_to_log_entry(j) {
                out.push(e);
                *budget -= 1;
            }
        } else if let Some(arr) = val.as_array() {
            for item in arr {
                if *budget == 0 {
                    return;
                }
                if let Some(o) = item.as_object() {
                    let mut j = Value::Object(o.clone());
                    if let Some(m) = j.as_object_mut() {
                        append_context(m, parser, template);
                        m.insert("source_path".to_string(), json!(path_key));
                    }
                    if let Ok(e) = json_to_log_entry(j) {
                        out.push(e);
                        *budget -= 1;
                    }
                }
            }
        }
    }
}

fn is_sqlite_tables_object(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    if obj.is_empty() {
        return false;
    }
    obj.values().all(|x| x.is_array())
}

fn extract_sqlite_shape(
    parser: &str,
    inner: &Value,
    template: &Value,
    budget: &mut usize,
    out: &mut Vec<LogEntry>,
) {
    let Some(root) = inner.as_object() else {
        return;
    };
    for (db_path, db_val) in root {
        if *budget == 0 {
            return;
        }
        let Some(tables) = db_val.as_object() else {
            continue;
        };
        if !tables.values().all(|x| x.is_array()) {
            continue;
        }
        for (table_name, rows_val) in tables {
            let Some(rows) = rows_val.as_array() else {
                continue;
            };
            for row in rows {
                if *budget == 0 {
                    return;
                }
                if let Some(o) = row.as_object() {
                    let mut j = Value::Object(o.clone());
                    if let Some(m) = j.as_object_mut() {
                        append_context(m, parser, template);
                        m.insert("sqlite_db_path".to_string(), json!(db_path));
                        m.insert("sqlite_table".to_string(), json!(table_name));
                        m.entry("event_type".to_string())
                            .or_insert(json!("sqlite_row"));
                    }
                    if let Ok(e) = json_to_log_entry(j) {
                        out.push(e);
                        *budget -= 1;
                    }
                }
            }
        }
    }
}

fn try_whole_output_as_entry(parser: &str, output: &Value) -> Option<LogEntry> {
    let obj = output.as_object()?;
    if obj.len() > MAX_SINGLE_OBJECT_KEYS {
        return None;
    }
    if obj.values().any(|v| match v {
        Value::String(s) => s.len() > 64 * 1024,
        Value::Array(a) => a.len() > 200,
        _ => false,
    }) {
        return None;
    }
    let mut j = output.clone();
    if let Some(m) = j.as_object_mut() {
        append_context(m, parser, output);
    }
    json_to_log_entry(j).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ps_rows_become_entries() {
        let v = json!({
            "parser": "ps",
            "source": "ps.txt",
            "rows": [
                { "user": "root", "pid": 1, "command": "/sbin/launchd" }
            ]
        });
        let e = extract_entries_for_parser(&ParserType::ps, &v).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(
            e[0].fields.get("command").and_then(|x| x.as_str()),
            Some("/sbin/launchd")
        );
    }

    #[test]
    fn crash_events_become_entries() {
        let v = json!({
            "parser": "crashlogs",
            "events": [{ "source": "x.ips", "format": "x", "data": { "name": "test" } }]
        });
        let e = extract_entries_for_parser(&ParserType::crashlogs, &v).unwrap();
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn utf8_map_paths_become_snippets() {
        let v = json!({
            "logs/foo/bar.log": "hello sigma world"
        });
        let e = extract_entries_for_parser(&ParserType::lockdownd, &v).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(
            e[0].fields.get("event_type").and_then(|x| x.as_str()),
            Some("text_snippet")
        );
    }

    #[test]
    fn bundled_example_sigma_rules_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sigma-rules");
        let mut engine = sigma_zero::engine::SigmaEngine::new(Some(1));
        let n = engine.load_rules(&dir).expect("load testdata/sigma-rules");
        assert!(
            n >= 4,
            "expected at least four example rules under testdata/sigma-rules, got {n}"
        );
    }
}
