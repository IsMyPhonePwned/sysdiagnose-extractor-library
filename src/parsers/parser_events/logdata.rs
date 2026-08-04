//! Ports of SAF [`logdata_statistics.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/logdata_statistics.py)
//! and [`logdata_statistics_txt.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/logdata_statistics_txt.py).

use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use super::common::saf_event_dict;

pub fn parse_logdata_statistics_jsonl(text: &str, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(t) else {
            continue;
        };
        let Some(unix) = record
            .get("unixTime")
            .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)))
        else {
            continue;
        };
        let secs = unix as i64;
        let nsecs = ((unix - secs as f64) * 1e9).max(0.0) as u32;
        let Some(dt_utc) = Utc.timestamp_opt(secs, nsecs).single() else {
            continue;
        };
        let dt = dt_utc.with_timezone(&FixedOffset::east_opt(0).unwrap());
        let rec_type = record
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("logd");
        let file = record.get("file").cloned().unwrap_or(Value::Null);
        let Some(pl) = record.get("processList").and_then(|v| v.as_array()) else {
            continue;
        };
        for proc in pl {
            let process = proc.get("process").and_then(|v| v.as_str()).unwrap_or("");
            let msg = format!("Logd {rec_type} while {process} is running");
            let data = json!({
                "process": process,
                "file": file.clone(),
            });
            out.push(saf_event_dict(
                module,
                dt,
                &format!("Logd {rec_type}"),
                &msg,
                data,
            ));
        }
    }
    out
}

pub fn parse_logdata_statistics_txt(text: &str, module: &str) -> Vec<Value> {
    static PROC: OnceLock<Regex> = OnceLock::new();
    let proc_re =
        PROC.get_or_init(|| Regex::new(r"- \[\s*(\d+),\s*([\d.]+),\s*(.*)\s*\]").expect("procs"));

    let mut out = Vec::new();
    let mut inside = false;
    let mut record_tpl: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut timestamp: Option<chrono::DateTime<chrono::FixedOffset>> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("--- !logd statistics record") {
            inside = true;
            record_tpl.clear();
            timestamp = None;
            continue;
        }
        if inside && line.starts_with("--- !") {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        if line.starts_with("time  :") {
            let time_str = line.splitn(2, ':').nth(1).map(|s| s.trim()).unwrap_or("");
            timestamp = parse_logdata_txt_timestamp(time_str);
            continue;
        }
        if line.starts_with("file  :") {
            if let Some(v) = line.splitn(2, ':').nth(1) {
                record_tpl.insert("file".into(), json!(v.trim()));
            }
            continue;
        }
        if line.starts_with("type  :") {
            if let Some(v) = line.splitn(2, ':').nth(1) {
                record_tpl.insert("type".into(), json!(v.trim()));
            }
            continue;
        }
        if line.starts_with("- [") {
            if let Some(cap) = proc_re.captures(line) {
                let process = cap.get(3).map(|m| m.as_str().trim()).unwrap_or("");
                if let Some(ts) = timestamp {
                    let rec_type = record_tpl
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("logd");
                    let mut data = record_tpl.clone();
                    data.insert("process".into(), json!(process));
                    let msg = format!("Logd {rec_type} while {process} is running");
                    out.push(saf_event_dict(
                        module,
                        ts,
                        &format!("Logd {rec_type}"),
                        &msg,
                        Value::Object(data),
                    ));
                }
            }
        }
    }
    out
}

fn parse_logdata_txt_timestamp(time_str: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(time_str, "%Y-%m-%d %H:%M:%S%z").ok()
}
