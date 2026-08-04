//! Port of SAF `parsers/shutdownlogs.py`, with iOS 26 rotated-log discovery
//! aligned to [mvt#830](https://github.com/mvt-project/mvt/issues/830) /
//! [mvt#834](https://github.com/mvt-project/mvt/pull/834).

use chrono::TimeZone;
use chrono::Utc;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::SysdiagnoseParser;
use globset::Error as GlobError;

/// Active + rotated shutdown logs from logarchive Extra and on-disk diagnostics.
const PATTERNS: &[&str] = &[
    "system_logs.logarchive/Extra/shutdown.log",
    "system_logs.logarchive/Extra/shutdown.*.log",
    "private/var/db/diagnostics/shutdown.log",
    "private/var/db/diagnostics/shutdown.*.log",
];

fn re_time_wait() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"After ([\d.]+)s,").expect("regex"))
}

fn re_client() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r".*: (\d+) \((.*)\).*").expect("regex"))
}

fn re_sigterm_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r".*\[(\d+)\].*").expect("regex"))
}

fn re_uuid() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        )
        .expect("regex")
    })
}

/// Split a shutdown-log client path into executable path + optional trailing binary UUID.
///
/// iOS 26 client records look like `/usr/sbin/filecoordinationd/<UUID>`. Only a final
/// component that is a complete UUID is stripped; otherwise the raw path is preserved.
fn split_client_path(binary_path: &str) -> (String, Option<String>) {
    let Some((parent, last)) = binary_path.rsplit_once('/') else {
        return (binary_path.to_string(), None);
    };
    if !parent.is_empty() && re_uuid().is_match(last) {
        return (parent.to_string(), Some(last.to_string()));
    }
    (binary_path.to_string(), None)
}

fn command_name(executable_path: &str) -> String {
    executable_path
        .rsplit_once('/')
        .map(|(_, name)| name.to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| executable_path.to_string())
}

fn parse_shutdown_text(text: &str, source_path: &str, events: &mut Vec<Value>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0usize;
    const CLIENTS: &str = "these clients are still here";
    const REMAINING: &str = "remaining client pid";
    const SIGTERM: &str = "SIGTERM";

    while index < lines.len() {
        if lines[index].contains(CLIENTS) {
            let mut running: HashMap<String, serde_json::Map<String, Value>> = HashMap::new();
            let mut time_waiting = 0.0f64;
            while index < lines.len() && !lines[index].contains(SIGTERM) {
                if lines[index].contains(CLIENTS) {
                    if let Some(c) = re_time_wait().captures(lines[index]) {
                        if let Some(n) = c.get(1).and_then(|m| m.as_str().parse::<f64>().ok()) {
                            time_waiting = n;
                        }
                    }
                }
                if lines[index].contains(REMAINING) {
                    if let Some(c) = re_client().captures(lines[index]) {
                        let pid = c.get(1).unwrap().as_str().to_string();
                        let binary_path = c.get(2).unwrap().as_str().to_string();
                        let (executable_path, uuid) = split_client_path(&binary_path);
                        let command = command_name(&executable_path);
                        running
                            .entry(pid.clone())
                            .and_modify(|m| {
                                m.insert("time_waiting".into(), json!(time_waiting));
                                let tw = m
                                    .get("times_waiting")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(1);
                                m.insert("times_waiting".into(), json!(tw + 1));
                            })
                            .or_insert_with(|| {
                                let mut m = serde_json::Map::new();
                                m.insert("pid".into(), json!(pid.parse::<i64>().unwrap_or(-1)));
                                // Raw client string from the log (may include trailing UUID).
                                m.insert("path".into(), json!(binary_path.clone()));
                                // Executable path with trailing binary UUID removed when present.
                                m.insert("executable_path".into(), json!(executable_path));
                                m.insert("command".into(), json!(command));
                                if let Some(u) = uuid {
                                    m.insert("uuid".into(), json!(u));
                                } else {
                                    m.insert("uuid".into(), Value::Null);
                                }
                                m.insert("source_path".into(), json!(source_path));
                                m.insert("time_waiting".into(), json!(time_waiting));
                                m.insert("times_waiting".into(), json!(1));
                                m
                            });
                    }
                }
                index += 1;
            }
            if index < lines.len() && lines[index].contains(SIGTERM) {
                if let Some(c) = re_sigterm_ts().captures(lines[index]) {
                    if let Some(ts) = c.get(1).and_then(|m| m.as_str().parse::<i64>().ok()) {
                        let dt = Utc.timestamp_opt(ts, 0).single();
                        for item in running.into_values() {
                            let mut ev = serde_json::Map::new();
                            if let Some(d) = dt {
                                ev.insert("datetime".into(), json!(d.to_rfc3339()));
                            }
                            ev.insert(
                                "message".into(),
                                json!(format!(
                                    "{} is still there during shutdown after {}s",
                                    item.get("command").and_then(|v| v.as_str()).unwrap_or(""),
                                    item.get("time_waiting")
                                        .and_then(|v| v.as_f64())
                                        .unwrap_or(0.0)
                                )),
                            );
                            ev.insert(
                                "timestamp_desc".into(),
                                json!("process running at shutdown"),
                            );
                            ev.insert("data".into(), Value::Object(item));
                            events.push(Value::Object(ev));
                        }
                    }
                }
            }
        }
        index += 1;
    }
}

pub struct ShutdownLogsParser;

impl SysdiagnoseParser for ShutdownLogsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files =
            matching_files_patterns(archive, PATTERNS).map_err(|e: GlobError| e.to_string())?;
        if files.is_empty() {
            return Ok(json!({
                "parser": "shutdownlogs",
                "events": [],
                "note": "No shutdown.log / shutdown.*.log under Extra/ or private/var/db/diagnostics/"
            }));
        }

        let mut events = Vec::new();
        let mut sources = Vec::new();
        for (path, bytes) in files {
            sources.push(path.to_string());
            let text = String::from_utf8_lossy(bytes);
            parse_shutdown_text(&text, path, &mut events);
        }

        Ok(json!({
            "parser": "shutdownlogs",
            "sources": sources,
            "events": events
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::SysdiagnoseArchive;
    use std::collections::HashMap;
    use std::sync::Arc;

    const SAMPLE_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn sample_block(client: &str, unix_ts: i64) -> String {
        format!(
            "these clients are still here:\n\
             After 3.0s, waiting...\n\
             remaining client pid: 4242 ({client})\n\
             SIGTERM: [{unix_ts}] shutting down\n"
        )
    }

    fn parse_files(files: Vec<(&str, String)>) -> Value {
        let mut m = HashMap::new();
        for (path, text) in files {
            m.insert(
                path.to_string(),
                Arc::from(text.into_bytes().into_boxed_slice()),
            );
        }
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        ShutdownLogsParser.parse(&arch).expect("shutdownlogs parse")
    }

    #[test]
    fn split_client_path_strips_trailing_uuid_only() {
        let with_uuid = format!("/usr/sbin/filecoordinationd/{SAMPLE_UUID}");
        let (exe, uuid) = split_client_path(&with_uuid);
        assert_eq!(exe, "/usr/sbin/filecoordinationd");
        assert_eq!(uuid.as_deref(), Some(SAMPLE_UUID));

        let (exe, uuid) = split_client_path("/usr/sbin/filecoordinationd");
        assert_eq!(exe, "/usr/sbin/filecoordinationd");
        assert!(uuid.is_none());
    }

    #[test]
    fn discovers_rotated_diagnostics_shutdown_log() {
        let client = format!("/usr/sbin/filecoordinationd/{SAMPLE_UUID}");
        let v = parse_files(vec![(
            "private/var/db/diagnostics/shutdown.0.log",
            sample_block(&client, 1_712_498_480),
        )]);
        assert_eq!(v["parser"], "shutdownlogs");
        assert_eq!(
            v["sources"].as_array().unwrap(),
            &vec![json!("private/var/db/diagnostics/shutdown.0.log")]
        );
        let events = v["events"].as_array().expect("events");
        assert_eq!(events.len(), 1);
        let data = &events[0]["data"];
        assert_eq!(data["path"], client);
        assert_eq!(data["executable_path"], "/usr/sbin/filecoordinationd");
        assert_eq!(data["command"], "filecoordinationd");
        assert_eq!(data["uuid"], SAMPLE_UUID);
        assert_eq!(
            data["source_path"],
            "private/var/db/diagnostics/shutdown.0.log"
        );
        assert!(events[0]["message"]
            .as_str()
            .unwrap()
            .contains("filecoordinationd is still there"));
    }

    #[test]
    fn discovers_rotated_extra_shutdown_log_and_plain_path() {
        let v = parse_files(vec![(
            "system_logs.logarchive/Extra/shutdown.0.log",
            sample_block("/sbin/launchd", 1_712_498_500),
        )]);
        let events = v["events"].as_array().expect("events");
        assert_eq!(events.len(), 1);
        let data = &events[0]["data"];
        assert_eq!(data["path"], "/sbin/launchd");
        assert_eq!(data["executable_path"], "/sbin/launchd");
        assert_eq!(data["command"], "launchd");
        assert!(data["uuid"].is_null());
    }

    #[test]
    fn parses_all_discovered_shutdown_logs() {
        let v = parse_files(vec![
            (
                "system_logs.logarchive/Extra/shutdown.log",
                sample_block("/usr/libexec/amfid", 1_712_498_480),
            ),
            (
                "system_logs.logarchive/Extra/shutdown.0.log",
                sample_block("/usr/libexec/containermanagerd", 1_712_498_490),
            ),
        ]);
        let sources = v["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 2);
        let events = v["events"].as_array().expect("events");
        assert_eq!(events.len(), 2);
        let cmds: Vec<&str> = events
            .iter()
            .filter_map(|e| e["data"]["command"].as_str())
            .collect();
        assert!(cmds.contains(&"amfid"));
        assert!(cmds.contains(&"containermanagerd"));
    }
}
