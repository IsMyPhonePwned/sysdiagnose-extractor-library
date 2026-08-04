//! Port of SAF `parsers/crashlogs.py` (`.ips` JSON + structured threads/stacks; summary log as events).

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::error::Error;
use std::path::Path;
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::compile_globs;
use crate::glob_match::matching_files;
use crate::parsers::crashlogs_ips::enrich_ips_report;
use crate::parsers::parser_events::{
    naive_with_offset, saf_event_dict, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

const EXCLUDE: &[&str] = &["WiFiLQMMetrics", "OTAUpdate"];

pub struct CrashlogsParser;

impl SysdiagnoseParser for CrashlogsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let set = compile_globs(&[
            "**/crashes_and_spins/**/*.ips",
            "**/CrashReporter/**/*.ips",
            "**/Library/Logs/CrashReporter/**/*.ips",
            "**/summaries/crashes_and_spins.log",
        ])?;
        let files = matching_files(archive, &set);
        let creation = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (path, bytes) in &files {
            if EXCLUDE.iter().any(|e| path.contains(e)) {
                continue;
            }
            let basename = Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if basename.starts_with('.') {
                continue;
            }
            if path.ends_with(".ips") {
                if let Some(ev) = parse_ips(path, bytes) {
                    let h = event_hash(&ev);
                    if seen.insert(h) {
                        events.push(ev);
                    }
                }
            }
        }

        for (path, bytes) in &files {
            if !path.ends_with("crashes_and_spins.log") {
                continue;
            }
            for ev in parse_summary_file(path, bytes, creation) {
                let h = summary_event_hash(&ev);
                if seen.insert(h) {
                    events.push(ev);
                }
            }
        }

        Ok(wrap_jsonl("crashlogs", events))
    }
}

fn parse_ips(path: &str, bytes: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines();
    let first = lines.next()?;
    let header: Value = serde_json::from_str(first).ok()?;
    let body_lines: Vec<&str> = lines.collect();
    let body = body_lines.join("\n");

    // Structured threads / images enrichment (keeps report_raw + ips_format).
    let mut data = enrich_ips_report(header, &body);
    let obj = data.as_object_mut()?;

    // SAF nests the body under `report` (JSON object or structured text map).
    if !obj.contains_key("report") {
        let report = process_ips_lines(&body_lines);
        if !report.as_object().map(|m| m.is_empty()).unwrap_or(true)
            || report.as_array().is_some()
        {
            obj.insert("report".into(), report);
        } else if !body.trim().is_empty() {
            // Preserve non-empty bodies that did not parse as structured maps.
            if let Ok(v) = serde_json::from_str::<Value>(body.trim()) {
                obj.insert("report".into(), v);
            }
        }
    }

    let (name_from_file, _) = metadata_from_filename(path, None);
    // SAF always sets `name` from the filename (overwrites header `name` when present).
    obj.insert("name".into(), json!(name_from_file));

    let timestamp = crash_timestamp(obj).unwrap_or_else(|| {
        Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap())
    });

    let message = crash_message(obj);
    let mut ev = saf_event_dict("crashlogs", timestamp, "crashlog", &message, data);
    if let Some(m) = ev.as_object_mut() {
        m.insert("source".into(), json!(path));
    }
    Some(ev)
}

fn crash_timestamp(data: &Map<String, Value>) -> Option<DateTime<FixedOffset>> {
    // Prefer report.captureTime / report.date (more precise), then header timestamp.
    let report = data.get("report").and_then(|v| v.as_object());
    if let Some(r) = report {
        if let Some(s) = r.get("captureTime").and_then(|v| v.as_str()) {
            if let Some(dt) = parse_crash_datetime(s) {
                return Some(dt);
            }
        }
        if let Some(s) = r.get("date").and_then(|v| v.as_str()) {
            if let Some(dt) = parse_crash_datetime(s) {
                return Some(dt);
            }
        }
    }
    if let Some(s) = data.get("timestamp").and_then(|v| v.as_str()) {
        return parse_crash_datetime(s);
    }
    if let Some(s) = data.get("captureTime").and_then(|v| v.as_str()) {
        return parse_crash_datetime(s);
    }
    if let Some(s) = data.get("date").and_then(|v| v.as_str()) {
        return parse_crash_datetime(s);
    }
    None
}

fn parse_crash_datetime(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim();
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }
    // `%Y-%m-%d %H:%M:%SZ` / ISO Z without offset colon variants
    for fmt in ["%Y-%m-%d %H:%M:%SZ", "%Y-%m-%dT%H:%M:%SZ"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive).with_timezone(&FixedOffset::east_opt(0)?));
        }
    }
    None
}

fn crash_message(data: &Map<String, Value>) -> String {
    let report = data.get("report");
    if let Some(reason) = report
        .and_then(|r| r.get("reason"))
        .or_else(|| data.get("reason"))
        .and_then(|v| v.as_str())
    {
        return format!("Crashlog: {reason}");
    }
    if let Some(proc) = report
        .and_then(|r| r.get("procName"))
        .or_else(|| data.get("procName"))
        .and_then(|v| v.as_str())
    {
        return format!("Crashlog: {proc}");
    }
    let name = data
        .get("name")
        .or_else(|| data.get("app_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    format!("Crashlog: {name}")
}

/// SAF `process_ips_lines`: JSON body, or key/value / sectioned text.
fn process_ips_lines(lines: &[&str]) -> Value {
    if lines.is_empty() {
        return json!({});
    }
    let joined = lines.join("\n");
    let trim = joined.trim();
    if trim.starts_with('{') && trim.ends_with('}') {
        if let Ok(v) = serde_json::from_str::<Value>(trim) {
            return v;
        }
    }

    let mut result = Map::new();
    let mut n = 0;
    let mut powerstats_key: Option<String> = None;

    while n < lines.len() {
        let line = lines[n].trim();
        if line.is_empty() {
            n += 1;
            continue;
        }
        if line == "EOF" {
            break;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            if key.contains("Powerstats") {
                let pk = value.split_whitespace().next().unwrap_or(value).to_string();
                powerstats_key = Some(pk.clone());
                let ps = result
                    .entry("Powerstats".to_string())
                    .or_insert_with(|| json!({}));
                if let Some(obj) = ps.as_object_mut() {
                    obj.entry(pk).or_insert_with(|| json!({}));
                }
            }

            if !value.is_empty() {
                insert_report_value(&mut result, powerstats_key.as_deref(), key, json!(value));
            } else {
                // Section header: collect following non-empty lines as an array (or map for ARM state).
                let mut section: Vec<Value> = Vec::new();
                let is_arm = key.contains("Thread") && key.contains("crashed with ARM Thread State");
                let is_binary = key.contains("Binary Images");
                let is_thread = key.contains("Thread");
                n += 1;
                while n < lines.len() {
                    let l = lines[n].trim();
                    if l.is_empty() {
                        break;
                    }
                    if is_arm {
                        section.push(json!(split_thread_crashes_with_arm_thread_state(l)));
                    } else if is_binary {
                        if let Some(img) = split_binary_images(l) {
                            section.push(json!(img));
                        } else {
                            section.push(json!(l));
                        }
                    } else if is_thread {
                        if let Some(fr) = split_thread(l) {
                            section.push(json!(fr));
                        } else {
                            section.push(json!(l));
                        }
                    } else {
                        section.push(json!(l));
                    }
                    n += 1;
                }
                let val = if is_arm {
                    // Flatten ARM register lines into one object (SAF merges updates).
                    let mut merged = Map::new();
                    for item in section {
                        if let Some(o) = item.as_object() {
                            for (k, v) in o {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    Value::Object(merged)
                } else {
                    json!(section)
                };
                insert_report_value(&mut result, powerstats_key.as_deref(), key, val);
                continue;
            }
        } else if let Some(pk) = &powerstats_key {
            let ps = result
                .entry("Powerstats".to_string())
                .or_insert_with(|| json!({}));
            if let Some(obj) = ps.as_object_mut() {
                let entry = obj.entry(pk.clone()).or_insert_with(|| json!({}));
                if let Some(inner) = entry.as_object_mut() {
                    let extra = inner
                        .entry("extra_data".to_string())
                        .or_insert_with(|| json!([]));
                    if let Some(arr) = extra.as_array_mut() {
                        arr.push(json!(lines[n].trim_end()));
                    }
                }
            }
        }

        n += 1;
    }

    Value::Object(result)
}

fn insert_report_value(
    result: &mut Map<String, Value>,
    powerstats_key: Option<&str>,
    key: &str,
    value: Value,
) {
    if let Some(pk) = powerstats_key {
        let ps = result
            .entry("Powerstats".to_string())
            .or_insert_with(|| json!({}));
        if let Some(obj) = ps.as_object_mut() {
            let entry = obj.entry(pk.to_string()).or_insert_with(|| json!({}));
            if let Some(inner) = entry.as_object_mut() {
                inner.insert(key.to_string(), value);
            }
        }
    } else {
        result.insert(key.to_string(), value);
    }
}

fn split_thread_crashes_with_arm_thread_state(line: &str) -> Map<String, Value> {
    let elements: Vec<&str> = line.split_whitespace().collect();
    let mut result = Map::new();
    let mut i = 0;
    while i + 1 < elements.len() {
        let k = elements[i];
        if !k.ends_with(':') {
            result.insert(
                "error".into(),
                json!(elements[i..].join(" ")),
            );
            break;
        }
        result.insert(k.trim_end_matches(':').to_string(), json!(elements[i + 1]));
        i += 2;
    }
    result
}

fn split_thread(line: &str) -> Option<Map<String, Value>> {
    let elements: Vec<&str> = line.split_whitespace().collect();
    if elements.len() < 6 {
        return None;
    }
    let mut m = Map::new();
    m.insert("id".into(), json!(elements[0]));
    m.insert("image_name".into(), json!(elements[1]));
    m.insert("image_base".into(), json!(elements[2]));
    m.insert("image_offset".into(), json!(elements[3]));
    m.insert("symbol_offset".into(), json!(elements[5]));
    Some(m)
}

fn split_binary_images(line: &str) -> Option<Map<String, Value>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\s*(\w+)\s+-\s+([^\s]+)\s+([^<]+)<([^>]+)>\s*(.*)")
            .expect("binary images regex")
    });
    let caps = re.captures(line)?;
    let mut m = Map::new();
    m.insert(
        "image_offset_start".into(),
        json!(caps.get(1)?.as_str().trim()),
    );
    m.insert(
        "image_offset_end".into(),
        json!(caps.get(2)?.as_str().trim()),
    );
    m.insert("image_name".into(), json!(caps.get(3)?.as_str().trim()));
    m.insert("uuid".into(), json!(caps.get(4)?.as_str().trim()));
    m.insert("path".into(), json!(caps.get(5)?.as_str().trim()));
    Some(m)
}

fn parse_summary_file(
    source: &str,
    bytes: &[u8],
    creation: DateTime<FixedOffset>,
) -> Vec<Value> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();

    for line in text.lines() {
        if !line.starts_with('/') {
            continue;
        }
        let path = line.split(',').next().unwrap_or(line).trim();
        if !seen_paths.insert(path.to_string()) {
            continue;
        }
        let (app, timestamp) = metadata_from_filename(path, Some(creation.timezone()));
        let filename = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(path)
            .to_string();
        let data = json!({
            "app_name": app,
            "name": app,
            "filename": filename,
            "path": path,
            "warning": "Timezone may be wrong, parsed local time as same timezone as sysdiagnose creation time",
        });
        let mut ev = saf_event_dict(
            "crashlogs",
            timestamp,
            "crashlog",
            &format!("Crashlog: {app}"),
            data,
        );
        if let Some(m) = ev.as_object_mut() {
            m.insert("source".into(), json!(source));
        }
        out.push(ev);
    }
    out
}

fn metadata_from_filename(
    filename: &str,
    tzinfo: Option<FixedOffset>,
) -> (String, DateTime<FixedOffset>) {
    static RE1: OnceLock<Regex> = OnceLock::new();
    static RE2: OnceLock<Regex> = OnceLock::new();
    let re1 = RE1.get_or_init(|| {
        Regex::new(r"/([^/]+)-(\d{4}-\d{2}-\d{2}-\d{6})")
            .expect("filename date regex")
    });
    let re2 = RE2.get_or_init(|| {
        Regex::new(r"/([^/]+)-(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})")
            .expect("filename date regex alt")
    });

    // Ensure we can match relative paths like `crashes_and_spins/foo-....ips`.
    let normalized = if filename.starts_with('/') {
        filename.to_string()
    } else {
        format!("/{filename}")
    };

    if let Some(caps) = re1.captures(&normalized) {
        let app = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        if let Ok(naive) =
            NaiveDateTime::parse_from_str(caps.get(2).unwrap().as_str(), "%Y-%m-%d-%H%M%S")
        {
            let dt = match tzinfo {
                Some(tz) => naive_with_offset(naive, tz),
                None => Utc
                    .from_utc_datetime(&naive)
                    .with_timezone(&FixedOffset::east_opt(0).unwrap()),
            };
            return (app, dt);
        }
    }
    if let Some(caps) = re2.captures(&normalized) {
        let app = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        if let Ok(naive) =
            NaiveDateTime::parse_from_str(caps.get(2).unwrap().as_str(), "%Y-%m-%d-%H-%M-%S")
        {
            let dt = match tzinfo {
                Some(tz) => naive_with_offset(naive, tz),
                None => Utc
                    .from_utc_datetime(&naive)
                    .with_timezone(&FixedOffset::east_opt(0).unwrap()),
            };
            return (app, dt);
        }
    }

    let app = Path::new(filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(filename)
        .to_string();
    (
        app,
        DateTime::from_timestamp(0, 0)
            .unwrap()
            .with_timezone(&FixedOffset::east_opt(0).unwrap()),
    )
}

/// SAF: `f"{timestamp[:-9]}-{name}"` using header `timestamp` / `name`.
fn event_hash(ev: &Value) -> String {
    let name = ev
        .pointer("/data/name")
        .or_else(|| ev.pointer("/data/app_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ts = ev
        .pointer("/data/timestamp")
        .or_else(|| ev.pointer("/data/captureTime"))
        .or_else(|| ev.pointer("/data/date"))
        .or_else(|| ev.pointer("/datetime"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Match SAF truncation of fractional+tz suffix when long enough.
    let ts_key = if ts.len() > 9 { &ts[..ts.len() - 9] } else { ts };
    format!("{ts_key}-{name}")
}

fn summary_event_hash(ev: &Value) -> String {
    let name = ev
        .pointer("/data/name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let dt = ev
        .get("datetime")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Prefer path uniqueness when available (summary can repeat names).
    if let Some(path) = ev.pointer("/data/path").and_then(|v| v.as_str()) {
        return format!("summary-{path}");
    }
    format!("{dt}-{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::SysdiagnoseArchive;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn parses_palera1n_style_two_part_ips_without_collapsing() {
        let mut files: HashMap<String, Arc<[u8]>> = HashMap::new();
        for (name, ts) in [
            ("palera1nHelper-2023-05-24-130825.ips", "2023-05-24 13:08:25.00 -0700"),
            ("palera1nHelper-2023-05-24-130843.ips", "2023-05-24 13:08:43.00 -0700"),
            ("palera1nHelper-2023-05-24-132608.ips", "2023-05-24 13:26:08.00 -0700"),
        ] {
            let body = format!(
                r#"{{"app_name":"palera1nHelper","timestamp":"{ts}","name":"palera1nHelper","bug_type":"309"}}
{{
  "procName" : "palera1nHelper",
  "exception" : {{ "type" : "EXC_CRASH", "signal" : "SIGABRT" }},
  "faultingThread" : 0,
  "usedImages" : [{{ "name" : "palera1nHelper", "uuid" : "U", "base" : 1 }}],
  "threads" : [{{ "id" : 0, "triggered" : true, "frames" : [{{ "imageIndex" : 0, "imageOffset" : 1, "symbol" : "main" }}] }}]
}}"#
            );
            files.insert(
                format!("crashes_and_spins/{name}"),
                Arc::from(body.into_bytes()),
            );
        }
        files.insert(
            "summaries/crashes_and_spins.log".into(),
            Arc::from(
                b"\n/private/var/mobile/Library/Logs/CrashReporter/palera1nHelper-2023-05-24-132608.ips, Added\n\
/private/var/mobile/Library/Logs/CrashReporter/palera1nHelper-2023-05-24-130825.ips, Added\n"
                    .as_slice(),
            ),
        );
        files.insert(
            "sysdiagnose.log".into(),
            Arc::from(
                b"IN_PROGRESS_sysdiagnose_2023.05.24_13-29-15-0700_iPhone-OS_iPhone_19H349/\n"
                    .as_slice(),
            ),
        );

        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let out = CrashlogsParser.parse(&arch).unwrap();
        assert_eq!(out["format"], "jsonl");
        let events = out["events"].as_array().unwrap();
        // 3 ips + 2 summary lines
        assert_eq!(events.len(), 5);

        let pal = events
            .iter()
            .filter(|e| {
                e["data"]["app_name"]
                    .as_str()
                    .is_some_and(|s| s == "palera1nHelper")
                    && e["source"].as_str().is_some_and(|s| s.ends_with(".ips"))
            })
            .count();
        assert_eq!(pal, 3);

        let one = events
            .iter()
            .find(|e| {
                e["source"]
                    .as_str()
                    .is_some_and(|s| s.contains("130825.ips"))
            })
            .unwrap();
        assert_eq!(one["module"], "crashlogs");
        assert_eq!(one["timestamp_desc"], "crashlog");
        assert!(one["message"].as_str().unwrap().contains("palera1nHelper"));
        assert_eq!(one["data"]["report"]["procName"], "palera1nHelper");
        assert_eq!(one["data"]["report"]["exception"]["type"], "EXC_CRASH");
        assert!(one["data"]["threads"].as_array().unwrap().len() >= 1);
    }

    #[test]
    fn parses_crashreporter_layout_ips() {
        let body = r#"{"app_name":"Signal","timestamp":"2025-04-07 07:41:58.00 -0700","name":"Signal","bug_type":"309"}
{
  "procName" : "Signal",
  "exception" : { "type" : "EXC_CRASH", "signal" : "SIGABRT" },
  "faultingThread" : 0,
  "usedImages" : [{ "name" : "Signal", "uuid" : "U", "base" : 1 }],
  "threads" : [{ "id" : 0, "triggered" : true, "frames" : [{ "imageIndex" : 0, "imageOffset" : 1, "symbol" : "main" }] }]
}"#;
        let mut files: HashMap<String, Arc<[u8]>> = HashMap::new();
        files.insert(
            "var/mobile/Library/Logs/CrashReporter/Signal.hooked-2025-04-07-074158.ips".into(),
            Arc::from(body.as_bytes()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let out = CrashlogsParser.parse(&arch).unwrap();
        let events = out["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["data"]["app_name"].as_str(), Some("Signal"));
    }

    #[test]
    fn metadata_from_relative_ips_path() {
        let (app, dt) =
            metadata_from_filename("crashes_and_spins/stacks-2023-05-24-132915.ips", None);
        assert_eq!(app, "stacks");
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-05-24 13:29:15");
    }
}
