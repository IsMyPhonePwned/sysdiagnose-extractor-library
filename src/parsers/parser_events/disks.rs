//! Port of SAF [`disks.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/disks.py).

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::common::saf_event_dict;
use crate::util::snake_case;

fn parse_size_to_bytes(size_str: &str) -> i64 {
    let s = size_str.trim();
    if s.is_empty() || s == "-" {
        return 0;
    }
    if let Ok(v) = s.parse::<i64>() {
        return v;
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r"(?i)^([0-9]+\.?[0-9]*)\s*([bkmgt])?\s*$").expect("size"));
    let collapsed = s.replace(' ', "");
    let cap = match re.captures(&collapsed) {
        Some(c) => c,
        None => return 0,
    };
    let num_str = cap.get(1).map(|m| m.as_str()).unwrap_or("0");
    let unit = cap
        .get(2)
        .map(|m| m.as_str().to_ascii_uppercase())
        .unwrap_or_default();
    let Ok(value) = num_str.parse::<f64>() else {
        return 0;
    };
    let factor: f64 = match unit.as_str() {
        "" | "B" => 1.0,
        "K" => 1024.0,
        "M" => 1024.0_f64.powi(2),
        "G" => 1024.0_f64.powi(3),
        "T" => 1024.0_f64.powi(4),
        _ => 1.0,
    };
    (value * factor) as i64
}

/// `header_length` fields per line; last field may contain spaces (mount path).
fn split_df_line(line: &str, header_length: usize) -> Option<Vec<String>> {
    if header_length == 0 {
        return None;
    }
    let mut it = line.split_whitespace();
    let mut out = Vec::with_capacity(header_length);
    for _ in 0..header_length.saturating_sub(1) {
        out.push(it.next()?.to_string());
    }
    let rest = it.collect::<Vec<_>>().join(" ");
    out.push(rest);
    Some(out)
}

pub fn parse_disks_txt(text: &str, module: &str, default_ts: DateTime<FixedOffset>) -> Vec<Value> {
    let mut lines = text.lines();
    let Some(header_line) = lines.next() else {
        return Vec::new();
    };
    let header_sane = header_line.replace("Mounted on", "Mounted_on");
    let header: Vec<String> = header_sane
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let header_length = header.len();
    if header_length == 0 {
        return Vec::new();
    }
    let normalized_header: Vec<String> = header.iter().map(|h| snake_case(h)).collect();
    let mut events = Vec::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some(fields) = split_df_line(line, header_length) else {
            continue;
        };
        let mut entry = Map::new();
        for (idx, col_name) in normalized_header.iter().enumerate() {
            let value = fields.get(idx).cloned().unwrap_or_default();
            entry.insert(col_name.clone(), json!(value));
        }

        for size_key in ["size", "used", "avail"] {
            if let Some(Value::String(s)) = entry.get(size_key) {
                entry.insert(format!("{size_key}_bytes"), json!(parse_size_to_bytes(s)));
            }
        }
        if let Some(Value::String(cap)) = entry.get("capacity") {
            if let Some(pct) = cap.strip_suffix('%').and_then(|x| x.parse::<f64>().ok()) {
                entry.insert("capacity_percent".into(), json!(pct));
            }
        }
        if let Some(Value::String(u)) = entry.get("use%") {
            let t = u.trim_end_matches('%');
            if let Ok(pct) = t.parse::<f64>() {
                entry.insert("use_percent".into(), json!(pct));
            }
        }

        let mount_point = entry
            .get("mounted_on")
            .or_else(|| entry.get("mount_point"))
            .or_else(|| entry.get("mounted"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let filesystem = entry
            .get("filesystem")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let msg = format!("Disk usage on {mount_point} ({filesystem})");

        events.push(saf_event_dict(
            module,
            default_ts,
            "sysdiagnose creation time",
            &msg,
            Value::Object(entry),
        ));
    }
    events
}
