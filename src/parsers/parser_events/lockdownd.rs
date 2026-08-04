//! Port of SAF [`lockdownd.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/lockdownd.py).

use chrono::{FixedOffset, NaiveDateTime};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::common::{naive_with_offset, saf_event_dict};
use super::{classify_ios_auth_message, stamp_auth_classification};

pub fn extract_lockdownd(text: &str, module: &str, tz: FixedOffset) -> Vec<Value> {
    let lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let mut i = 0usize;
    let mut out = Vec::new();
    static NEXT_ENTRY: OnceLock<Regex> = OnceLock::new();
    static LINE_RE: OnceLock<Regex> = OnceLock::new();
    let next_entry = NEXT_ENTRY.get_or_init(|| Regex::new(r"^.{24} pid=\d+ ").expect("next"));
    let line_re = LINE_RE.get_or_init(|| {
        Regex::new(r"(?s)(^.{24}) pid=(\d+) ([^:]+): (.*)$").expect("lockdownd line")
    });

    while i < lines.len() {
        let mut current = lines[i].clone();
        loop {
            let next_idx = i + 1;
            if next_idx < lines.len() && next_entry.is_match(&lines[next_idx]) {
                break;
            }
            if next_idx >= lines.len() {
                break;
            }
            current.push('\n');
            current.push_str(&lines[next_idx]);
            i += 1;
        }

        if let Some(cap) = line_re.captures(&current) {
            let ts_raw = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let pid: i64 = cap
                .get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(-1);
            let event_type = cap.get(3).map(|m| m.as_str()).unwrap_or("");
            let message = cap.get(4).map(|m| m.as_str().trim()).unwrap_or("");
            if let Ok(naive) = NaiveDateTime::parse_from_str(ts_raw, "%m/%d/%y %H:%M:%S.%f") {
                let dt = naive_with_offset(naive, tz);
                let mut data = Map::new();
                data.insert("pid".into(), json!(pid));
                data.insert("lockdownd_event_type".into(), json!(event_type));
                // Preserve legacy key used by some consumers.
                data.insert("event_type".into(), json!(event_type));

                let timestamp_desc = if let Some(auth) = classify_ios_auth_message(message) {
                    stamp_auth_classification(&mut data, auth);
                    // Prefer authentication_event over raw lockdownd function name.
                    data.insert("lockdownd_event_type".into(), json!(event_type));
                    auth.timestamp_desc.to_string()
                } else {
                    format!("lockdownd {event_type}")
                };

                out.push(saf_event_dict(
                    module,
                    dt,
                    &timestamp_desc,
                    message,
                    Value::Object(data),
                ));
            }
        }
        i += 1;
    }
    out
}
