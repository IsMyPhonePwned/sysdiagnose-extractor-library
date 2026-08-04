//! Port of SAF [`wifiscan.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifiscan.py).

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::common::saf_event_dict;

pub fn parse_wifi_scan(text: &str, module: &str, default_ts: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = if line.starts_with("total=") {
            parse_summary(line)
        } else {
            parse_line(line)
        };
        let message = if let Some(Value::String(ref ssid)) = parsed.get("ssid") {
            let sec = parsed
                .get("security")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ch = parsed.get("channel").and_then(|v| v.as_str()).unwrap_or("");
            format!("{ssid} {sec} {ch}")
        } else {
            let concatenated: Vec<String> = parsed
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| format!("{k}={s}")))
                .collect();
            format!("Wifi scan: {}", concatenated.join(", "))
        };
        out.push(saf_event_dict(
            module,
            default_ts,
            "wifi scan at sysdiagnose creation",
            &message,
            Value::Object(parsed.clone()),
        ));
    }
    out
}

fn parse_summary(line: &str) -> Map<String, Value> {
    let mut parsed = Map::new();
    for item in line.split(',') {
        let Some((k, v)) = item.split_once('=') else {
            continue;
        };
        parsed.insert(k.trim().to_string(), json!(v.trim()));
    }
    parsed
}

fn parse_line(line: &str) -> Map<String, Value> {
    let mut parsed = Map::new();
    static R1: OnceLock<Regex> = OnceLock::new();
    static R2: OnceLock<Regex> = OnceLock::new();
    static R3: OnceLock<Regex> = OnceLock::new();
    static R4: OnceLock<Regex> = OnceLock::new();
    let r1 =
        R1.get_or_init(|| Regex::new(r"(?P<ssid>.+?) - ssid=(?P<ssid_hex>[^,]+)").expect("r1"));
    let r2 =
        R2.get_or_init(|| Regex::new(r"'(?P<ssid>[^\']+)' \((?P<ssid_hex>[^\)]+)\)").expect("r2"));
    let r3 =
        R3.get_or_init(|| Regex::new(r"'(?P<ssid>[^\']+)' \<(?P<ssid_hex>[^>]+)\>").expect("r3"));
    let r4 = R4.get_or_init(|| Regex::new(r"(?P<ssid><HIDDEN>)(?P<ssid_hex>)").expect("r4"));
    for r in [r1, r2, r3, r4] {
        if let Some(cap) = r.captures(line) {
            parsed.insert(
                "ssid".into(),
                json!(cap.name("ssid").map(|m| m.as_str()).unwrap_or("")),
            );
            let hex = cap
                .name("ssid_hex")
                .map(|m| m.as_str().replace(' ', ""))
                .unwrap_or_default();
            parsed.insert("ssid_hex".into(), json!(hex));
            break;
        }
    }
    if !parsed.contains_key("ssid") {
        parsed.insert("ssid".into(), json!("<unknown>"));
    }
    let Some(idx) = line.find(',') else {
        return parsed;
    };
    let mut index_now = idx + 1;
    while index_now < line.len() {
        let Some(index_equals) = line[index_now..].find('=').map(|i| i + index_now) else {
            break;
        };
        let key = line[index_now..index_equals].trim().to_string();
        let after_eq = index_equals + 1;
        if after_eq >= line.len() {
            break;
        }
        let (value, index_close) = if line.as_bytes().get(after_eq) == Some(&b'[') {
            let start = after_eq + 1;
            let close = line[start..]
                .find(']')
                .map(|i| i + start)
                .unwrap_or(line.len());
            let value = line[start..close].trim().to_string();
            (value, close)
        } else {
            let close = line[after_eq..]
                .find(',')
                .map(|i| i + after_eq)
                .unwrap_or(line.len());
            let value = line[after_eq..close].trim().to_string();
            (value, close)
        };
        parsed.insert(key, json!(value));
        index_now = index_close + 2;
        if index_now > line.len() {
            break;
        }
    }
    parsed
}
