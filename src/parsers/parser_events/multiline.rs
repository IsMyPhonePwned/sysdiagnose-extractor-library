//! Port of SAF [`multilinelog.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/multilinelog.py).

use chrono::{FixedOffset, NaiveDateTime};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::common::{naive_with_offset, saf_event_dict};

#[derive(Clone, Copy, PartialEq, Eq)]
enum KvSection {
    None,
    Start,
    Active,
    End,
}

/// Apple multiline log (`Mon Jan  2 15:04:05 2006 [pid] <level> (0xhex)-[type]: message`).
pub fn extract_multiline_log(text: &str, module: &str, tz: FixedOffset) -> Vec<Value> {
    let mut events = Vec::new();
    let mut prev_lines: Vec<String> = Vec::new();
    let mut kv_section = KvSection::None;

    for raw_line in text.lines() {
        let line = raw_line.to_string();
        let has_ts = timestamp_at_line_start(&line).is_some();
        if line.contains("_____") && kv_section_start_pat().is_match(&line) {
            kv_section = KvSection::Start;
        }

        let ts_flush = has_ts
            && matches!(
                kv_section,
                KvSection::None | KvSection::Start | KvSection::End
            );

        if ts_flush {
            if kv_section == KvSection::Start {
                kv_section = KvSection::Active;
            }
            if kv_section == KvSection::End {
                kv_section = KvSection::None;
                if let Some(ev) = build_from_kv_section(&mut prev_lines.clone(), tz, module) {
                    events.push(ev);
                }
                prev_lines.clear();
                continue;
            } else if !prev_lines.is_empty() {
                if let Some(ev) = build_from_logentry(&prev_lines.join(""), tz, module) {
                    events.push(ev);
                }
            }
            prev_lines.clear();
            prev_lines.push(line.clone());
        } else if !prev_lines.is_empty() || kv_section == KvSection::Active {
            prev_lines.push(line.clone());
        }

        if kv_section == KvSection::Active
            && line.contains("_____")
            && kv_section_end_pat().is_match(&line)
        {
            kv_section = KvSection::End;
        }
    }

    if !prev_lines.is_empty() {
        let ev = if kv_section == KvSection::Active && prev_lines.len() > 1 {
            build_from_kv_section(&mut prev_lines.clone(), tz, module)
        } else {
            build_from_logentry(&prev_lines.join(""), tz, module)
        };
        if let Some(e) = ev {
            events.push(e);
        }
    }

    events
}

fn kv_section_start_pat() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r": _{10,25} [^_]+ _{10,25}").expect("kv start"))
}

fn kv_section_end_pat() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r": _{40,80}$").expect("kv end"))
}

fn timestamp_at_line_start(line: &str) -> Option<regex::Captures<'_>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(.+?) \[\d+\]").expect("ts"));
    re.captures(line)
}

fn build_from_kv_section(lines: &mut Vec<String>, tz: FixedOffset, module: &str) -> Option<Value> {
    if lines.is_empty() {
        return None;
    }
    let first = lines.remove(0);
    let mut event = build_from_logentry(&first, tz, module)?;
    let obj = event.get_mut("data")?.as_object_mut()?;
    if let Some(last) = lines.last() {
        if last.contains("_____") {
            lines.pop();
        }
    }
    for l in lines.iter() {
        let parts: Vec<&str> = l.split(':').collect();
        if parts.len() > 1 {
            let key = parts[parts.len() - 2].trim();
            let val = parts[parts.len() - 1].trim();
            obj.insert(key.to_string(), Value::String(val.to_string()));
        }
    }
    Some(event)
}

fn build_from_logentry(line: &str, tz: FixedOffset, module: &str) -> Option<Value> {
    static TS: OnceLock<Regex> = OnceLock::new();
    static LV: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static ET: OnceLock<Regex> = OnceLock::new();
    let ts_re = TS.get_or_init(|| Regex::new(r"^(.+?) \[\d+\]").unwrap());
    let loglevel_re = LV.get_or_init(|| Regex::new(r"<(.*?)>").unwrap());
    let hex_re = HEX.get_or_init(|| Regex::new(r"\(0x(.*?)\)").unwrap());
    let etype_re = ET.get_or_init(|| Regex::new(r"\-\[(.*)(\]\:)").unwrap());

    let cap_ts = ts_re.captures(line)?;
    let timestamp_str = cap_ts.get(1)?.as_str();
    let naive = NaiveDateTime::parse_from_str(timestamp_str, "%a %b %d %H:%M:%S %Y").ok()?;
    let dt = naive_with_offset(naive, tz);

    let mut entry = Map::new();
    let loglevel = loglevel_re.captures(line)?.get(1)?.as_str();
    entry.insert("loglevel".into(), json!(loglevel));
    let hexid = hex_re.captures(line)?.get(1)?.as_str();
    entry.insert("hexID".into(), json!(format!("0x{hexid}")));
    if let Some(m) = etype_re.captures(line) {
        entry.insert("event_type".into(), json!(m.get(1)?.as_str()));
    }

    let (message, plist_val) = extract_message_and_plist(line, entry.contains_key("event_type"));
    if let Some(p) = plist_val {
        entry.insert("plist".into(), p);
    }

    Some(saf_event_dict(
        module,
        dt,
        &format!("{module} event"),
        &message,
        Value::Object(entry),
    ))
}

fn extract_message_and_plist(line: &str, has_event_type: bool) -> (String, Option<Value>) {
    static MSG_BRACKET: OnceLock<Regex> = OnceLock::new();
    static MSG_PAREN: OnceLock<Regex> = OnceLock::new();
    let msg_bracket = MSG_BRACKET.get_or_init(|| Regex::new(r"\]\:(.*)").unwrap());
    let msg_paren = MSG_PAREN.get_or_init(|| Regex::new(r"\)\ (.*)").unwrap());

    let rest = if has_event_type {
        msg_bracket
            .captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim())
            .unwrap_or("")
    } else {
        msg_paren
            .captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim())
            .unwrap_or("")
    };

    if rest.ends_with("</plist>") {
        if let Some(idx) = rest.find("<?xml version") {
            let message = rest[..idx].trim().to_string();
            let plist_xml = &rest[idx..];
            let plist_val =
                plist::from_reader::<_, plist::Value>(std::io::Cursor::new(plist_xml.as_bytes()))
                    .ok()
                    .and_then(|v| serde_json::to_value(v).ok());
            return (message, plist_val);
        }
    }
    (rest.to_string(), None)
}
