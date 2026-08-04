//! Port of SAF [`kbdebug.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/kbdebug.py).

use chrono::DateTime;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use super::common::saf_event_dict;

pub fn parse_kbdebug_log(text: &str, module: &str) -> Vec<Value> {
    static TS: OnceLock<Regex> = OnceLock::new();
    static CHUNK: OnceLock<Regex> = OnceLock::new();
    let ts_re = TS.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+\d{4}").expect("kbdebug ts")
    });
    let chunk_re = CHUNK.get_or_init(|| {
        Regex::new(r"(?s)^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+\d{4}): (\w+): (.*)$")
            .expect("chunk")
    });

    let matches: Vec<(usize, usize)> = ts_re
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect();
    let mut out = Vec::new();
    for (i, (start, _end)) in matches.iter().enumerate() {
        let end = matches
            .get(i + 1)
            .map(|(s, _)| *s)
            .unwrap_or_else(|| text.len());
        let chunk = text.get(*start..end).unwrap_or("").trim_end();
        let Some(cap) = chunk_re.captures(chunk) else {
            continue;
        };
        let ts_raw = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let level = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let message = cap.get(3).map(|m| m.as_str().trim()).unwrap_or("");
        let Ok(dt) = DateTime::parse_from_str(ts_raw, "%Y-%m-%d %H:%M:%S %z") else {
            continue;
        };
        out.push(saf_event_dict(
            module,
            dt,
            "kbdebug event",
            message,
            json!({ "level": level }),
        ));
    }
    out
}
