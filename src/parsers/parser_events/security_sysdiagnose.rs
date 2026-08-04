//! Port of SAF [`security_sysdiagnose.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/src/sysdiagnose/parsers/security_sysdiagnose.py).

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::warn;

use super::common::saf_event_dict;

const MODULE: &str = "security_sysdiagnose";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BufferSection {
    Circle,
    EngineState,
    KeychainState,
    Analytics,
    Client,
    KeysAndValues,
}

fn re_keychain_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})").expect("regex")
    })
}

fn re_client_line_24h() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}) ([^:]+): (.+?) - Attributes: \{(.*)",
        )
        .expect("regex")
    })
}

fn re_client_line_ampm() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2} [AP]M [+-]\d{4}) ([^:]+): (.+?) - Attributes: \{(.*)",
        )
        .expect("regex")
    })
}

fn re_attr_pair() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\w+)\s*:\s*(\([^)]+\)|.+?)(?:, |$)").expect("regex"))
}

fn parse_keychain_ts(s: &str) -> Option<DateTime<FixedOffset>> {
    let cap = re_keychain_ts().captures(s.trim())?;
    let t = cap.get(1)?.as_str();
    DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S %z")
        .ok()
        .map(|d| d.with_timezone(&FixedOffset::east_opt(0).unwrap()))
}

fn parse_client_ts_24h(s: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S %z").ok()
}

fn parse_client_ts_ampm(s: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(s.trim(), "%Y-%m-%d %I:%M:%S %p %z").ok()
}

/// Parse `security-sysdiagnose.txt` into SAF-style event dicts (same fields as upstream `Event.to_dict`).
pub fn parse_security_sysdiagnose(content: &str, creation: DateTime<FixedOffset>) -> Vec<Value> {
    let mut acc = JsonResult::default();
    let mut buffer: Vec<String> = Vec::new();
    let mut buffer_section: Option<BufferSection> = None;

    for raw in content.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("ccstatus:") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::Circle);
            buffer = vec![line.to_string()];
        } else if line.starts_with("Engine state:") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::EngineState);
            buffer.clear();
        } else if line.ends_with("keychain state:") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::KeychainState);
            buffer = vec![line.to_string()];
        } else if line.starts_with("Analytics sysdiagnose") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::Analytics);
            buffer.clear();
        } else if line.starts_with("Client:") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::Client);
            buffer = vec![line.to_string()];
        } else if line.starts_with("All keys and values") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::KeysAndValues);
            buffer = vec!["keysandvalues".to_string()];
        } else if line.starts_with("All values in") {
            process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
            buffer_section = Some(BufferSection::KeysAndValues);
            buffer = vec!["values".to_string()];
        } else {
            buffer.push(line.to_string());
        }
    }

    process_buffer(&mut buffer, buffer_section.take(), &mut acc, creation);
    append_meta_as_events(&mut acc, creation);
    acc.events
}

#[derive(Default)]
struct JsonResult {
    events: Vec<Value>,
    /// Mirrors Python `json_result['meta']` — order preserved for stable extra events.
    meta: Vec<(String, Value)>,
}

fn meta_get_mut_map<'a>(
    meta: &'a mut Vec<(String, Value)>,
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    meta.iter_mut()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_object_mut())
}

fn meta_get_mut_array<'a>(
    meta: &'a mut Vec<(String, Value)>,
    key: &str,
) -> Option<&'a mut Vec<Value>> {
    meta.iter_mut()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_array_mut())
}

fn meta_set(meta: &mut Vec<(String, Value)>, key: &str, val: Value) {
    if let Some((k, v)) = meta.iter_mut().find(|(k, _)| k == key) {
        *v = val;
        let _ = k;
        return;
    }
    meta.push((key.to_string(), val));
}

fn process_buffer(
    buffer: &mut Vec<String>,
    section: Option<BufferSection>,
    json_result: &mut JsonResult,
    creation: DateTime<FixedOffset>,
) {
    let Some(section) = section else {
        return;
    };
    match section {
        BufferSection::Circle => process_buffer_circle(buffer, json_result),
        BufferSection::EngineState => process_buffer_engine_state(buffer, json_result),
        BufferSection::KeychainState => {
            process_buffer_keychain_state(buffer, json_result, creation)
        }
        BufferSection::Analytics => process_buffer_analytics(buffer, json_result),
        BufferSection::Client => process_buffer_client(buffer, json_result),
        BufferSection::KeysAndValues => process_buffer_keys_and_values(buffer, json_result),
    }
}

fn process_buffer_circle(buffer: &[String], json_result: &mut JsonResult) {
    let arr: Vec<Value> = buffer.iter().cloned().map(Value::String).collect();
    meta_set(&mut json_result.meta, "circle", Value::Array(arr));
}

fn process_buffer_engine_state(buffer: &[String], json_result: &mut JsonResult) {
    let arr: Vec<Value> = buffer.iter().cloned().map(Value::String).collect();
    meta_set(&mut json_result.meta, "engine", Value::Array(arr));
}

fn process_buffer_keychain_state(
    buffer: &mut Vec<String>,
    json_result: &mut JsonResult,
    _creation: DateTime<FixedOffset>,
) {
    if buffer.is_empty() {
        return;
    }
    let header = buffer.remove(0);
    let section = header
        .split_whitespace()
        .next()
        .unwrap_or("keychain")
        .trim_end_matches(':')
        .to_ascii_lowercase();

    meta_set(&mut json_result.meta, &section, Value::Array(Vec::new()));

    for line in buffer.drain(..) {
        let row_map = parse_keychain_kv_line(&line);
        let row_obj: Map<String, Value> = row_map
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();

        if row_map.contains_key("cdat") || row_map.contains_key("mdat") {
            let desc = row_map
                .get("desc")
                .or_else(|| row_map.get("labl"))
                .cloned()
                .unwrap_or_default();
            let agrp = row_map.get("agrp").cloned().unwrap_or_default();
            let msg = format!("{section} {desc} - {agrp}");
            let attrs = Value::Object(row_obj.clone());

            if let Some(cdat) = row_map.get("cdat") {
                match parse_keychain_ts(cdat) {
                    Some(ts) => {
                        let ev = saf_event_dict(
                            MODULE,
                            ts,
                            &format!("{section}: entry creation time"),
                            &msg,
                            json!({ "section": section, "attributes": attrs.clone() }),
                        );
                        json_result.events.push(ev);
                    }
                    None => warn!(line = %line, "security_sysdiagnose: cannot parse cdat"),
                }
            }
            if let Some(mdat) = row_map.get("mdat") {
                match parse_keychain_ts(mdat) {
                    Some(ts) => {
                        let ev = saf_event_dict(
                            MODULE,
                            ts,
                            &format!("{section}: entry modification time"),
                            &msg,
                            json!({ "section": section, "attributes": attrs }),
                        );
                        json_result.events.push(ev);
                    }
                    None => warn!(line = %line, "security_sysdiagnose: cannot parse mdat"),
                }
            }
        } else if let Some(arr) = meta_get_mut_array(&mut json_result.meta, &section) {
            arr.push(Value::Object(row_obj));
        }
    }
}

fn parse_keychain_kv_line(line: &str) -> HashMap<String, String> {
    let mut row = HashMap::new();
    let rest = if let Some(i) = line.find(": ") {
        &line[i + 2..]
    } else {
        line
    };
    let chars: Vec<char> = rest.chars().collect();
    let mut subsection = false;
    let mut key: Option<String> = None;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '}' => subsection = false,
            '{' => subsection = true,
            '=' if key.is_none() && !subsection => {
                let k: String = chars[start..i].iter().collect();
                key = Some(k);
                start = i + 1;
            }
            ',' if !subsection => {
                if let Some(ref k) = key {
                    let v: String = chars[start..i].iter().collect();
                    row.insert(k.clone(), v);
                }
                start = i + 1;
                key = None;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(ref k) = key {
        let v: String = chars[start..].iter().collect();
        row.insert(k.clone(), v);
    }
    row
}

fn process_buffer_analytics(_buffer: &[String], _json_result: &mut JsonResult) {}

fn process_buffer_client(buffer: &mut Vec<String>, json_result: &mut JsonResult) {
    if buffer.is_empty() {
        return;
    }
    let client_line = buffer.remove(0);
    let section_suffix = client_line
        .split(':')
        .nth(1)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let section = format!("client_{section_suffix}");

    if buffer.is_empty() {
        return;
    }
    if buffer[0].starts_with("No data") {
        return;
    }

    let mut i = 0usize;
    while i < buffer.len() {
        let line = &buffer[i];
        let (ts, result, client_event, mut attr_tail) =
            if let Some(cap) = re_client_line_24h().captures(line) {
                let ts_s = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let ts = match parse_client_ts_24h(ts_s) {
                    Some(t) => t,
                    None => {
                        warn!(line = %line, "security_sysdiagnose: client 24h timestamp");
                        i += 1;
                        continue;
                    }
                };
                let result = cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                let client_event = cap.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
                let tail = cap.get(4).map(|m| m.as_str()).unwrap_or("").to_string();
                (ts, result, client_event, tail)
            } else if let Some(cap) = re_client_line_ampm().captures(line) {
                let ts_s = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let ts = match parse_client_ts_ampm(ts_s) {
                    Some(t) => t,
                    None => {
                        warn!(line = %line, "security_sysdiagnose: client AM/PM timestamp");
                        i += 1;
                        continue;
                    }
                };
                let result = cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                let client_event = cap.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
                let tail = cap.get(4).map(|m| m.as_str()).unwrap_or("").to_string();
                (ts, result, client_event, tail)
            } else {
                warn!(line = %line, "security_sysdiagnose: client line no match");
                i += 1;
                continue;
            };

        let mut j = i;
        while j + 1 < buffer.len() && !starts_with_date_prefix(&buffer[j + 1]) {
            j += 1;
            attr_tail.push_str(&buffer[j]);
        }

        let mut attr_clean = attr_tail.chars().filter(|c| *c != '\n').collect::<String>();
        attr_clean = attr_clean.trim().to_string();
        if attr_clean.ends_with('}') {
            attr_clean.pop();
        }
        attr_clean = attr_clean.trim().to_string();

        let mut attrs = Map::new();
        for cap in re_attr_pair().captures_iter(&attr_clean) {
            let key = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            let val = cap.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if !key.is_empty() {
                attrs.insert(key.to_string(), json!(val));
            }
        }

        let message = format!("{section} {result} {client_event}");
        let ev = saf_event_dict(
            MODULE,
            ts,
            &client_event,
            &message,
            json!({
                "section": section,
                "result": result,
                "event": client_event,
                "attributes": Value::Object(attrs),
            }),
        );
        json_result.events.push(ev);
        i = j + 1;
    }
}

fn starts_with_date_prefix(s: &str) -> bool {
    let t = s.trim_start();
    t.len() >= 10
        && t.as_bytes().get(4) == Some(&b'-')
        && t.as_bytes().get(7) == Some(&b'-')
        && t.chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
}

fn process_buffer_keys_and_values(buffer: &mut Vec<String>, json_result: &mut JsonResult) {
    if buffer.is_empty() {
        return;
    }
    let section = buffer.remove(0);
    meta_set(&mut json_result.meta, &section, Value::Object(Map::new()));

    let mut i = 0usize;
    while i < buffer.len() {
        let mut line = buffer[i].clone();
        let mut j = i;
        while j + 1 < buffer.len() && buffer[j + 1].starts_with('\t') {
            j += 1;
            line.push('\n');
            line.push_str(&buffer[j]);
        }
        if let Some((k, v)) = line.split_once(": ") {
            if let Some(m) = meta_get_mut_map(&mut json_result.meta, &section) {
                m.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
            }
        }
        i = j + 1;
    }
}

fn append_meta_as_events(json_result: &mut JsonResult, creation: DateTime<FixedOffset>) {
    for (root_key, items) in &json_result.meta {
        if let Value::Array(arr) = items {
            for item in arr {
                let item_str = match item {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let message = format!("{root_key} {item_str}");
                let ev = saf_event_dict(
                    MODULE,
                    creation,
                    "security meta event",
                    &message,
                    json!({
                        "item": item.clone(),
                        "timestamp_info": "sysdiagnose creation time",
                        "section": root_key,
                        "attributes": Value::Object(Map::new()),
                    }),
                );
                json_result.events.push(ev);
            }
        } else if let Value::Object(obj) = items {
            for (key, item) in obj {
                let message = format!("{root_key} {key}: {item}");
                let ev = saf_event_dict(
                    MODULE,
                    creation,
                    "security meta event",
                    &message,
                    json!({
                        "timestamp_info": "sysdiagnose creation time",
                        "section": root_key,
                        "attributes": item.clone(),
                    }),
                );
                json_result.events.push(ev);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed() -> DateTime<FixedOffset> {
        FixedOffset::east_opt(3600)
            .unwrap()
            .with_ymd_and_hms(2024, 6, 1, 12, 0, 0)
            .unwrap()
    }

    /// CPython `isoformat` uses `+00:00`; chrono may emit `Z` for UTC.
    fn assert_dt_pythonish(ev: &Value, want: &str) {
        let got = ev.get("datetime").and_then(|x| x.as_str()).unwrap();
        let got_norm = got.replacen('Z', "+00:00", 1);
        assert_eq!(got_norm, want, "datetime field mismatch");
    }

    /// [`test_process_buffer_keychain_state`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/test_parsers_security_sysdiagnose.py)
    #[test]
    fn upstream_test_process_buffer_keychain_state() {
        let mut acc = JsonResult::default();
        let mut buf = vec![
            "Rapport keychain state:".to_string(),
            "rapport: accc=,acct=69AAAFE9-A7FA-4BF3-922E-A14C33F11924,agrp=com.apple.rapport,cdat=2023-05-24 19:56:14 +0000,gena={length = 33, bytes = 0xe3456d6f 64656c49 6950686f 6e65392c ... 6973696f 6e494409 },invi=1,labl=iPhone,mdat=2023-05-24 19:56:14 +0000,musr={length = 0, bytes = 0x},pdmn=ck,sha1={length = 20, bytes = 0x1490ff273a003ef4089c46beb3731eb04754c7e5},svce=RPIdentity-SameAccountDevice,sync=1,tomb=0,vwht=Home".to_string(),
        ];
        process_buffer_keychain_state(&mut buf, &mut acc, fixed());
        let rapport_meta = acc
            .meta
            .iter()
            .find(|(k, _)| k == "rapport")
            .and_then(|(_, v)| v.as_array());
        assert!(
            rapport_meta.is_some_and(|a| a.is_empty()),
            "rows with cdat/mdat should not populate meta list: {:?}",
            rapport_meta
        );
        assert_eq!(acc.events.len(), 2, "{:?}", acc.events);
        for ev in &acc.events {
            assert_eq!(ev["module"], MODULE);
            assert_dt_pythonish(ev, "2023-05-24T19:56:14.000000+00:00");
            assert_eq!(ev["message"], "rapport iPhone - com.apple.rapport");
            let attrs = ev["data"]["attributes"].as_object().unwrap();
            assert_eq!(
                attrs.get("acct").and_then(|x| x.as_str()),
                Some("69AAAFE9-A7FA-4BF3-922E-A14C33F11924")
            );
            assert_eq!(
                attrs.get("agrp").and_then(|x| x.as_str()),
                Some("com.apple.rapport")
            );
            assert_eq!(attrs.get("labl").and_then(|x| x.as_str()), Some("iPhone"));
        }
        assert_eq!(
            acc.events[0]["timestamp_desc"],
            "rapport: entry creation time"
        );
        assert_eq!(
            acc.events[1]["timestamp_desc"],
            "rapport: entry modification time"
        );
    }

    /// [`test_process_buffer_client`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/test_parsers_security_sysdiagnose.py)
    #[test]
    fn upstream_test_process_buffer_client() {
        let mut acc = JsonResult::default();
        let mut buf = vec![
            "Client: trust".to_string(),
            "2023-05-24 19:55:51 +0000 EventSoftFailure: OTAPKIEvent - Attributes: {product : iPhone OS, build : 19H349, errorDomain : NSOSStatusErrorDomain, modelid : iPhone9,3, errorCode : -67694 }".to_string(),
            "2023-05-24 19:57:58 +0000 EventSoftFailure: MitmDetectionEvent - Attributes: {product : iPhone OS, build : 19H349, overallScore : 0, timeSinceLastReset : 127, rootUsages : (".to_string(),
            " foo, bar ".to_string(),
            "), errorDomain : MITMErrorDomain, modelid : iPhone9,3, errorCode : 0 }".to_string(),
            "2024-09-06 9:45:15 AM +0000 EventHardFailure: CloudServicesSetConfirmedManifest - Attributes: {product : macOS, build : 22H121, errorDomain : NSOSStatusErrorDomain, modelid : MacBookPro14,3, errorCode : -25308 }".to_string(),
        ];
        process_buffer_client(&mut buf, &mut acc);
        assert_eq!(acc.events.len(), 3, "{:?}", acc.events);
        assert_eq!(acc.events[0]["module"], MODULE);
        assert_dt_pythonish(&acc.events[0], "2023-05-24T19:55:51.000000+00:00");
        assert_eq!(acc.events[0]["timestamp_desc"], "OTAPKIEvent");
        assert_eq!(
            acc.events[0]["message"],
            "client_trust EventSoftFailure OTAPKIEvent"
        );
        let a0 = acc.events[0]["data"]["attributes"].as_object().unwrap();
        assert_eq!(
            a0.get("product").and_then(|x| x.as_str()),
            Some("iPhone OS")
        );
        assert_eq!(a0.get("errorCode").and_then(|x| x.as_str()), Some("-67694"));

        assert_dt_pythonish(&acc.events[1], "2023-05-24T19:57:58.000000+00:00");
        assert_eq!(acc.events[1]["timestamp_desc"], "MitmDetectionEvent");
        let a1 = acc.events[1]["data"]["attributes"].as_object().unwrap();
        assert_eq!(
            a1.get("rootUsages").and_then(|x| x.as_str()),
            Some("( foo, bar )")
        );

        assert_dt_pythonish(&acc.events[2], "2024-09-06T09:45:15.000000+00:00");
        assert_eq!(
            acc.events[2]["timestamp_desc"],
            "CloudServicesSetConfirmedManifest"
        );
        let a2 = acc.events[2]["data"]["attributes"].as_object().unwrap();
        assert_eq!(a2.get("product").and_then(|x| x.as_str()), Some("macOS"));
    }

    /// [`test_process_buffer_keys_and_values`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/test_parsers_security_sysdiagnose.py)
    #[test]
    fn upstream_test_process_buffer_keys_and_values() {
        let mut acc = JsonResult::default();
        let mut buf = vec![
            "values".to_string(),
            "~PCS-Notes-tomb: {length = 7741, capacity = 7741, bytes = 0x30821e39314c300e0c0a4170706c6963 ... 8df3270d7d823100}".to_string(),
        ];
        process_buffer_keys_and_values(&mut buf, &mut acc);
        let m = meta_get_mut_map(&mut acc.meta, "values").expect("values meta");
        let v = m
            .get("~PCS-Notes-tomb")
            .and_then(|x| x.as_str())
            .expect("tomb key");
        assert!(v.contains("30821e39314c300e0c0a4170706c6963"));
        assert!(v.contains("7741"));
    }

    #[test]
    fn keychain_row_with_cdat_emits_event() {
        let text = r"Genp keychain state:
desc=testdesc,agrp=testgrp,cdat=2020-01-02 03:04:05 +0000
";
        let evs = parse_security_sysdiagnose(text, fixed());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["data"]["section"], "genp");
    }

    #[test]
    fn keys_and_values_meta_event() {
        let text = r"All keys and values
foo: bar
";
        let evs = parse_security_sysdiagnose(text, fixed());
        assert_eq!(evs.len(), 1);
        assert!(evs[0]["message"]
            .as_str()
            .unwrap()
            .contains("keysandvalues"));
        assert!(evs[0]["message"].as_str().unwrap().contains("foo"));
    }

    #[test]
    fn client_24h_line() {
        let text = r"Client: trust
2020-01-02 15:30:00 +0000 Result: Something happened - Attributes: {k1: v1, k2: (x)}
";
        let evs = parse_security_sysdiagnose(text, fixed());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["data"]["section"], "client_trust");
    }
}
