//! Port of SAF [`wifisecurity.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifisecurity.py).

use chrono::DateTime;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::common::saf_event_dict;

pub fn parse_wifi_security(text: &str, module: &str) -> Vec<Value> {
    let mut entries = Vec::new();
    let mut element: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        if line.contains(" : ") {
            let mut parts = line.splitn(2, " : ");
            let key = parts.next().unwrap_or("").trim().to_string();
            let value = parts.next().unwrap_or("").trim().to_string();
            element.insert(key, value);
        } else if !element.is_empty() {
            let Some(cdat) = element.get("cdat") else {
                element.clear();
                continue;
            };
            if let Ok(dt) = DateTime::parse_from_str(cdat, "%Y-%m-%d %H:%M:%S %z") {
                let desc = element.get("desc").cloned().unwrap_or_default();
                let labl = element.get("labl").cloned().unwrap_or_default();
                let acct = element.get("acct").cloned().unwrap_or_default();
                let msg = format!("Wifi AP config: {desc} # {labl} # {acct}");
                let data: Map<String, Value> = element
                    .iter()
                    .map(|(k, v)| (k.clone(), json!(v.clone())))
                    .collect();
                entries.push(saf_event_dict(
                    module,
                    dt,
                    "wifi AP config created",
                    &msg,
                    Value::Object(data.clone()),
                ));
                if let Some(mdat) = element.get("mdat") {
                    if mdat != cdat {
                        if let Ok(dt2) = DateTime::parse_from_str(mdat, "%Y-%m-%d %H:%M:%S %z") {
                            entries.push(saf_event_dict(
                                module,
                                dt2,
                                "wifi AP config modified",
                                &msg,
                                Value::Object(data),
                            ));
                        }
                    }
                }
            }
            element.clear();
        }
    }
    entries
}
