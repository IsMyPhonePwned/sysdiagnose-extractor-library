//! Port of SAF [`swcutil.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/swcutil.py).

use chrono::{DateTime, FixedOffset};
use regex::{Captures, Regex};
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use crate::util::snake_case;

use super::common::saf_event_dict;

const MODULE: &str = "swcutil";

const BANNER_DB: &str =
    "=================================== DATABASE ===================================";
const BANNER_NETWORK: &str =
    "=================================== NETWORK ====================================";
const BANNER_SETTINGS: &str =
    "=================================== SETTINGS ===================================";
const BANNER_MEMORY: &str =
    "================================= MEMORY USAGE =================================";
const SEP_DB: &str =
    "--------------------------------------------------------------------------------";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Headers,
    Db,
    Network,
    Settings,
    Memory,
}

/// Parse `swcutil_show.txt` body into SAF-shaped events (same section model as upstream `parse_file`).
pub fn parse_swcutil_show(text: &str, creation: DateTime<FixedOffset>) -> Vec<Value> {
    let mut headers: Vec<String> = Vec::new();
    let mut db: Vec<String> = Vec::new();
    let mut network: Vec<String> = Vec::new();
    let mut settings: Vec<String> = Vec::new();
    let mut memory_events: Vec<Value> = Vec::new();
    let mut section = Section::Headers;

    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t == BANNER_DB {
            section = Section::Db;
            continue;
        }
        if t == BANNER_NETWORK {
            section = Section::Network;
            continue;
        }
        if t == BANNER_SETTINGS {
            section = Section::Settings;
            continue;
        }
        if t == BANNER_MEMORY {
            section = Section::Memory;
            continue;
        }
        match section {
            Section::Headers => headers.push(t.to_string()),
            Section::Db => db.push(t.to_string()),
            Section::Network => network.push(t.to_string()),
            Section::Settings => settings.push(t.to_string()),
            Section::Memory => {
                if let Some(ev) = parse_memory_entry(t, creation) {
                    memory_events.push(ev);
                }
            }
        }
    }

    let mut out = memory_events;
    out.push(parse_headers_entry(&headers, creation));
    out.extend(parse_db(&db, creation));
    out.extend(parse_settings(&settings, creation));
    out.extend(parse_network(&network, creation));
    out
}

fn parse_basic_lines(lines: &[String]) -> Map<String, Value> {
    let mut m = Map::new();
    for line in lines {
        let mut sp = line.splitn(2, ':');
        let k = sp.next().unwrap_or("").trim();
        let v = sp.next().map(str::trim).unwrap_or("");
        if k.is_empty() {
            continue;
        }
        let key = snake_case(k);
        if !key.is_empty() {
            m.insert(key, Value::String(v.to_string()));
        }
    }
    m.insert("module".into(), json!(MODULE));
    m
}

fn parse_headers_entry(headers: &[String], creation: DateTime<FixedOffset>) -> Value {
    let mut entry = parse_basic_lines(headers);
    entry.insert("section".into(), json!("headers"));
    let data = Value::Object(entry);
    saf_event_dict(
        MODULE,
        creation,
        "swcutil headers at sysdiagnose creation",
        "swcutil headers",
        data,
    )
}

fn parse_network(data: &[String], creation: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    for line in data {
        for part in line.split(", ") {
            let domain = part.split_whitespace().next().unwrap_or("").trim();
            if domain.is_empty() {
                continue;
            }
            let data = json!({
                "domain": domain,
                "section": "network"
            });
            let msg = format!("Network: {domain}");
            out.push(saf_event_dict(
                MODULE,
                creation,
                "sysdiagnose creation time",
                &msg,
                data,
            ));
        }
    }
    out
}

fn normalize_ios182_last_checked(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(\d{4}-\d{2}-\d{2}\s+)(\d):").expect("hour pad"));
    re.replace_all(s, |c: &Captures| {
        let g1 = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let g2 = c.get(2).map(|m| m.as_str()).unwrap_or("");
        format!("{g1}0{g2}:")
    })
    .into_owned()
}

fn parse_db(data: &[String], creation: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut buf: Vec<String> = Vec::new();
    for line in data {
        if line.trim() == SEP_DB {
            if !buf.is_empty() {
                out.push(parse_db_entry(&buf, creation));
            }
            buf.clear();
        } else {
            buf.push(line.clone());
        }
    }
    if !buf.is_empty() {
        out.push(parse_db_entry(&buf, creation));
    }
    out
}

fn parse_db_entry(buffer: &[String], creation: DateTime<FixedOffset>) -> Value {
    let mut entry = parse_basic_lines(buffer);
    entry.insert("section".into(), json!("db"));
    let data = Value::Object(entry.clone());

    let (ts, ts_desc) = match entry.get("last_checked").and_then(|v| v.as_str()) {
        Some(lc) => {
            let norm = normalize_ios182_last_checked(lc);
            if let Ok(dt) = DateTime::parse_from_str(&norm, "%Y-%m-%d %H:%M:%S %z") {
                (dt, "db last checked")
            } else if let Ok(dt) = DateTime::parse_from_str(&norm, "%Y-%m-%d %I:%M:%S %p %z") {
                (dt, "db last checked")
            } else {
                (creation, "sysdiagnose creation time")
            }
        }
        None => (creation, "sysdiagnose creation time"),
    };

    let svc = entry.get("service").and_then(|v| v.as_str()).unwrap_or("?");
    let app = entry.get("app_id").and_then(|v| v.as_str()).unwrap_or("?");
    let dom = entry.get("domain").and_then(|v| v.as_str()).unwrap_or("?");
    let msg = format!("{svc}: {app} for {dom}");
    saf_event_dict(MODULE, ts, ts_desc, &msg, data)
}

fn parse_settings(data: &[String], creation: DateTime<FixedOffset>) -> Vec<Value> {
    if data.first().map(|s| s.as_str()) == Some("(empty)") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut buf: Vec<String> = Vec::new();
    for line in data {
        if line.trim() == SEP_DB {
            if !buf.is_empty() {
                if let Some(ev) = parse_settings_entry(&buf, creation) {
                    out.push(ev);
                }
            }
            buf.clear();
        } else {
            buf.push(line.clone());
        }
    }
    if !buf.is_empty() {
        if let Some(ev) = parse_settings_entry(&buf, creation) {
            out.push(ev);
        }
    }
    out
}

fn settings_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\{\s*s\s*=\s*(?P<s>[^,]+),\s*a\s*=\s*(?P<a>[^,]+),\s*d\s*=\s*(?P<d>[^}]+)\s*\}",
        )
        .expect("settings header")
    })
}

fn settings_kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""([^"]+)"\s*=\s*([^;]+);"#).expect("settings kv"))
}

fn parse_settings_entry(buffer: &[String], creation: DateTime<FixedOffset>) -> Option<Value> {
    let s: String = buffer.iter().cloned().collect();
    let cap = settings_header_re().captures(&s)?;
    let s_val = cap.name("s").map(|m| m.as_str().trim()).unwrap_or("");
    let a_val = cap.name("a").map(|m| m.as_str().trim()).unwrap_or("");
    let d_val = cap.name("d").map(|m| m.as_str().trim()).unwrap_or("");

    let mut settings_map = Map::new();
    for c in settings_kv_re().captures_iter(&s) {
        let key = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let val = c.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if !key.is_empty() {
            settings_map.insert(snake_case(key), json!(val));
        }
    }

    let mut entry = Map::new();
    entry.insert("section".into(), json!("settings"));
    entry.insert("s".into(), json!(s_val));
    entry.insert("a".into(), json!(a_val));
    entry.insert("d".into(), json!(d_val));
    entry.insert("settings".into(), Value::Object(settings_map));

    let data = Value::Object(entry);
    let msg = format!("swcutil settings {s_val} {a_val}");
    Some(saf_event_dict(
        MODULE,
        creation,
        "sysdiagnose creation time",
        &msg,
        data,
    ))
}

fn parse_memory_entry(line: &str, creation: DateTime<FixedOffset>) -> Option<Value> {
    let mut sp = line.splitn(2, ':');
    let proc = sp.next()?.trim();
    let value = sp.next()?.trim();
    if proc.is_empty() {
        return None;
    }

    let mut entry = Map::new();
    entry.insert("section".into(), json!("memory"));
    entry.insert("process".into(), json!(proc));

    let usage = if value.contains("bytes") || value.contains("octets") {
        value.split_whitespace().next()?.parse::<i64>().ok()
    } else if value.contains("KB") || value.contains("ko") {
        value
            .split_whitespace()
            .next()?
            .parse::<i64>()
            .ok()
            .map(|n| n * 1024)
    } else if value.contains("MB") || value.contains("mo") {
        value
            .split_whitespace()
            .next()?
            .parse::<i64>()
            .ok()
            .map(|n| n * 1024 * 1024)
    } else if value.contains("GB") || value.contains("go") {
        value
            .split_whitespace()
            .next()?
            .parse::<i64>()
            .ok()
            .map(|n| n * 1024_i64 * 1024 * 1024)
    } else {
        None
    };

    let mut msg = proc.to_string();
    if let Some(u) = usage {
        entry.insert("usage".into(), json!(u));
        msg.push_str(&format!(" memory usage: {u} bytes"));
    }

    let data = Value::Object(entry);
    Some(saf_event_dict(
        MODULE,
        creation,
        "memory usage at sysdiagnose creation",
        &msg,
        data,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed() -> DateTime<FixedOffset> {
        FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2024, 6, 1, 12, 0, 0)
            .unwrap()
    }

    #[test]
    fn swcutil_headers_db_network_memory() {
        let text = r"PID:                  1
Storage:              /tmp

=================================== DATABASE ===================================
Service:              webcredentials
App ID:               com.apple.test
Domain:               example.com
Last Checked:         2020-01-02 3:04:05 +0000
--------------------------------------------------------------------------------
=================================== NETWORK ====================================
example.com approved, wallet.apple.com pending
=================================== SETTINGS ===================================
(empty)
================================= MEMORY USAGE =================================
kernel_task: 2 MB
";
        let evs = parse_swcutil_show(text, fixed());
        assert!(
            evs.iter().any(|e| e["message"] == "swcutil headers"),
            "{evs:?}"
        );
        assert!(evs.iter().any(|e| e["message"] == "Network: example.com"));
        assert!(evs
            .iter()
            .any(|e| e["message"] == "Network: wallet.apple.com"));
        let db_ev = evs
            .iter()
            .find(|e| e["timestamp_desc"] == "db last checked")
            .expect("db event");
        assert!(db_ev["message"]
            .as_str()
            .unwrap()
            .contains("webcredentials"));
        let mem = evs
            .iter()
            .find(|e| e["data"]["section"] == "memory")
            .expect("memory");
        assert_eq!(mem["data"]["usage"], 2 * 1024 * 1024);
    }

    #[test]
    fn swcutil_settings_block() {
        let text = concat!(
            "=================================== SETTINGS ===================================\n",
            "{ s = applinks, a = com.apple.AppStore, d = (null) }: {\n",
            "  \"com.apple.LaunchServices.enabled\" = 1;\n",
            "}\n",
            "--------------------------------------------------------------------------------\n",
        );
        let evs = parse_swcutil_show(text, fixed());
        let s = evs.iter().find(|e| e["data"]["section"] == "settings");
        assert!(s.is_some());
        let ev = s.unwrap();
        assert_eq!(ev["data"]["s"], "applinks");
        assert_eq!(ev["data"]["a"], "com.apple.AppStore");
    }
}
