//! Timeline-style extracts from plist / JSON structures (SAF `mcsettingsevents`, `mcstate_shared_profile`,
//! `olddsc`, `mobilebackup`, `transparency`).

use chrono::{DateTime, FixedOffset, NaiveDateTime};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::common::{naive_utc, saf_event_dict};

/// Port of SAF [`transparency.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/transparency.py) `extract_events`.
pub fn transparency_extract_events(root: &Value, module: &str) -> Vec<Value> {
    let mut events = Vec::new();
    if let Some(reg) = root.get("registration").and_then(|v| v.as_array()) {
        for item in reg {
            let Some(obj) = item.as_object() else {
                continue;
            };
            let app_s = obj.get("app").and_then(|v| v.as_str()).unwrap_or("");
            for (k, v) in obj {
                if k.contains("At") {
                    if let Some(s) = v.as_str() {
                        if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %z") {
                            events.push(saf_event_dict(
                                module,
                                dt,
                                "app registration",
                                &format!("Transparency: registration app {app_s} {k}"),
                                json!({}),
                            ));
                        }
                    }
                }
            }
        }
    }
    let Some(sm) = root.get("stateMachine").and_then(|v| v.as_object()) else {
        return events;
    };
    if let Some(s) = sm.get("accountFirstSeen").and_then(|v| v.as_str()) {
        if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %z") {
            events.push(saf_event_dict(
                module,
                dt,
                "stateMachine",
                "Transparency: stateMachine accountFirstSeen",
                json!({}),
            ));
        }
    }
    if let Some(bo) = sm.get("backgroundOp").and_then(|v| v.as_object()) {
        for key in ["lastDutyCycle", "lastSuccess"] {
            if let Some(s) = bo.get(key).and_then(|v| v.as_str()) {
                if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
                    let dt = naive_utc(naive);
                    events.push(saf_event_dict(
                        module,
                        dt,
                        "stateMachine",
                        &format!("Transparency: stateMachine backgroundOp {key}"),
                        json!({}),
                    ));
                }
            }
        }
    }
    if let Some(lasts) = sm.get("lasts").and_then(|v| v.as_object()) {
        for (k, t) in lasts {
            if let Some(ts) = t.as_str() {
                if let Ok(dt) = DateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S %z") {
                    events.push(saf_event_dict(
                        module,
                        dt,
                        "stateMachine",
                        &format!("Transparency: stateMachine last {k}"),
                        json!({}),
                    ));
                }
            }
        }
    }
    if let Some(launch) = sm.get("launch").and_then(|v| v.as_array()) {
        for entry in launch {
            let Some(s) = entry.as_str() else { continue };
            let mut parts = s.splitn(2, " - ");
            let t = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");
            if let Ok(dt) = DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f%z") {
                events.push(saf_event_dict(
                    module,
                    dt,
                    "stateMachine",
                    &format!("Transparency: stateMachine launch {key}"),
                    json!({}),
                ));
            }
        }
    }
    if let Some(ls) = sm.get("lockState").and_then(|v| v.as_str()) {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}").expect("lockstate")
        });
        if let Some(m) = re.find(ls) {
            if let Ok(dt) = DateTime::parse_from_str(m.as_str(), "%Y-%m-%d %H:%M:%S %z") {
                events.push(saf_event_dict(
                    module,
                    dt,
                    "stateMachine",
                    "Transparency: stateMachine lockState",
                    json!({}),
                ));
            }
        }
    }
    if let Some(ops) = sm.get("ops").and_then(|v| v.as_object()) {
        static RE2: OnceLock<Regex> = OnceLock::new();
        let re2 = RE2.get_or_init(|| {
            Regex::new(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})").expect("ops ts")
        });
        for (_k, val) in ops {
            let Some(vs) = val.as_str() else { continue };
            if let Some(m) = re2.captures(vs) {
                if let Ok(dt) = DateTime::parse_from_str(&m[1], "%Y-%m-%d %H:%M:%S %z") {
                    events.push(saf_event_dict(
                        module,
                        dt,
                        "stateMachine",
                        &format!("Transparency: stateMachine ops {vs}"),
                        json!({}),
                    ));
                }
            }
        }
    }
    events
}

/// SAF [`mcsettingsevents.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/mcsettingsevents.py).
pub fn mc_settings_events(plist: &Value, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    traverse_mc(plist, module, "", &mut out);
    out
}

fn traverse_mc(data: &Value, module: &str, path: &str, out: &mut Vec<Value>) {
    let Some(obj) = data.as_object() else {
        return;
    };
    for (key, value) in obj {
        let current_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let Some(inner) = value.as_object() else {
            continue;
        };
        if let Some(Value::String(ts_s)) = inner.get("timestamp") {
            if let Ok(naive) = NaiveDateTime::parse_from_str(ts_s, "%Y-%m-%dT%H:%M:%S%.f") {
                let dt = naive_utc(naive);
                let mut data_obj = inner.clone();
                data_obj.remove("timestamp");
                let event = data_obj
                    .get("event")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let process = data_obj
                    .get("process")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let msg = format!("setting {current_path} {event} by {process}");
                let mut d = Map::new();
                for (k, v) in data_obj {
                    d.insert(k, v.clone());
                }
                d.insert("setting".into(), json!(current_path.clone()));
                out.push(saf_event_dict(
                    module,
                    dt,
                    &format!("{module} {event}"),
                    &msg,
                    Value::Object(d),
                ));
            }
        } else {
            traverse_mc(value, module, &current_path, out);
        }
    }
}

/// SAF [`mcstate_shared_profile.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/mcstate_shared_profile.py).
pub fn mcstate_shared_profile_events(plist: &Value, module: &str) -> Option<Vec<Value>> {
    let obj = plist.as_object()?;
    let ts_s = obj.get("InstallDate")?.as_str()?;
    let naive = NaiveDateTime::parse_from_str(ts_s, "%Y-%m-%dT%H:%M:%S.%f").ok()?;
    let dt = naive_utc(naive);
    let msg = format!(
        "# {} # {} # {}",
        obj.get("PayloadDescription")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        obj.get("PayloadDisplayName")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        obj.get("PayloadOrganization")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    let ptype = obj
        .get("PayloadType")
        .and_then(|v| v.as_str())
        .unwrap_or("MCState");
    let data = Value::Object(obj.clone());
    Some(vec![saf_event_dict(
        module,
        dt,
        &format!("MCState {ptype}"),
        &msg,
        data,
    )])
}

/// SAF [`olddsc.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/olddsc.py).
pub fn olddsc_events(plist: &Value, module: &str, default_ts: DateTime<FixedOffset>) -> Vec<Value> {
    let Some(binaries) = plist.get("Binaries").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in binaries {
        let Some(e) = entry.as_object() else { continue };
        let path = e.get("Path").and_then(|v| v.as_str()).unwrap_or("");
        let uuid = e.get("UUID_String").and_then(|v| v.as_str()).unwrap_or("");
        let msg = format!("olddsc {path} {uuid}");
        let mut d = e.clone();
        d.insert("timestamp_info".into(), json!("sysdiagnose creation time"));
        out.push(saf_event_dict(
            module,
            default_ts,
            "olddsc",
            &msg,
            Value::Object(d),
        ));
    }
    out
}

/// SAF [`mobilebackup.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/mobilebackup.py) (active paths only).
pub fn mobilebackup_events(
    plist: &Value,
    module: &str,
    default_ts: DateTime<FixedOffset>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(root) = plist.as_object() else {
        return out;
    };
    if let Some(errors) = root
        .get("BackupStateInfo")
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("errors"))
        .and_then(|v| v.as_array())
    {
        for item in errors {
            let Some(obj) = item.as_object() else {
                continue;
            };
            let Some(date_s) = obj.get("date").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(naive) = NaiveDateTime::parse_from_str(date_s, "%Y-%m-%dT%H:%M:%S.%f") else {
                continue;
            };
            let dt = naive_utc(naive);
            let mut d = obj.clone();
            d.remove("date");
            let domain = obj.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let desc = obj
                .get("localizedDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let msg = format!("MobileBackup: {desc} in {domain} ");
            out.push(saf_event_dict(
                module,
                dt,
                "BackupStateInfo error",
                &msg,
                Value::Object(d),
            ));
        }
    }
    if let Some(pref) = root.get("PreflightSizing").and_then(|v| v.as_object()) {
        static RE1: OnceLock<Regex> = OnceLock::new();
        static RE2: OnceLock<Regex> = OnceLock::new();
        let re_bundle = RE1.get_or_init(|| Regex::new(r"[^-]+Domain[^-]*-(.+)$").expect("bundle"));
        let re_domain = RE2.get_or_init(|| Regex::new(r"([^-]+Domain[^-]*)").expect("domain"));
        for (key, value) in pref {
            let mut item = Map::new();
            item.insert("type".into(), json!("MobileBackup PreflightSizing entry"));
            item.insert("timestamp_info".into(), json!("sysdiagnose creation"));
            item.insert("key".into(), json!(key));
            item.insert("size".into(), value.clone());
            if let Some(m) = re_bundle.captures(key) {
                item.insert(
                    "bundle_id".into(),
                    json!(m.get(1).map(|g| g.as_str()).unwrap_or("")),
                );
            }
            if let Some(m) = re_domain.captures(key) {
                item.insert(
                    "domain".into(),
                    json!(m.get(1).map(|g| g.as_str()).unwrap_or("")),
                );
            }
            let bundle = item.get("bundle_id").and_then(|v| v.as_str()).unwrap_or("");
            let msg = format!(
                "{} bundle={bundle} key={key}",
                item.get("type").and_then(|v| v.as_str()).unwrap_or("")
            );
            out.push(saf_event_dict(
                module,
                default_ts,
                "PreflightSizing entry",
                &msg,
                Value::Object(item),
            ));
        }
    }
    out
}
