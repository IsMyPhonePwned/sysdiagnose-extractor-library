//! TCC (privacy) permissions rollup per app bundle id from `accessibility_tcc`.

use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::parsers::ParserType;

use super::common::{get_or_parse, value_looks_like_hard_error, ParsedByParser};

fn field_str(data: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = data.get(*k).and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let tcc = get_or_parse(archive, parsed, ParserType::accessibility_tcc);
    let mut apps: Map<String, Value> = Map::new();

    if !value_looks_like_hard_error(&tcc) {
        if let Some(events) = tcc.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                let Some(data) = ev.get("data").and_then(|d| d.as_object()) else {
                    continue;
                };
                let Some(client) = field_str(data, &["client", "CLIENT"]) else {
                    continue;
                };
                let perm = json!({
                    "service": field_str(data, &["service", "SERVICE"]),
                    "allowed": field_str(data, &["allowed", "ALLOWED"]),
                    "last_modified": ev.get("datetime").cloned().unwrap_or(Value::Null),
                    "auth_reason": field_str(data, &["auth_reason", "auth reason", "AUTH REASON"]),
                    "client_type": field_str(data, &["client_type", "client type", "CLIENT TYPE"]),
                    "indirect_object_identifier": field_str(data, &[
                        "indirect_object_identifier",
                        "indirect object identifier",
                        "INDIRECT OBJECT IDENTIFIER",
                    ]),
                    "source_db": data.get("source_db").cloned().unwrap_or(Value::Null),
                    "apollo_module": data.get("apollo_module").cloned().unwrap_or(Value::Null),
                });

                match apps.get_mut(&client) {
                    Some(Value::Object(app)) => {
                        if let Some(arr) = app.get_mut("permissions").and_then(|p| p.as_array_mut()) {
                            arr.push(perm);
                        }
                    }
                    _ => {
                        let mut app = Map::new();
                        app.insert("permissions".into(), json!([perm]));
                        apps.insert(client, Value::Object(app));
                    }
                }
            }
        }
    }

    for app in apps.values_mut() {
        if let Some(arr) = app.get_mut("permissions").and_then(|p| p.as_array_mut()) {
            arr.sort_by(|a, b| {
                let sa = a
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sb = b
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                sa.cmp(sb)
            });
        }
    }

    json!({
        "analyser": "permissions",
        "app_count": apps.len(),
        "apps": apps,
        "source_parser": "accessibility_tcc",
        "saf_comparison": "Rolls up APOLLO TCC.db rows (privacy services only — not full iOS Settings permissions). Requires TCC.db in the archive.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn rolls_up_tcc_events_by_bundle_id() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "accessibility_tcc".into(),
            json!({
                "parser": "accessibility_tcc",
                "format": "jsonl",
                "events": [
                    {
                        "datetime": "2023-11-14T22:13:20Z",
                        "data": {
                            "client": "com.example.cam",
                            "service": "kTCCServiceCamera",
                            "allowed": "ALLOWED",
                            "source_db": "logs/Accessibility/TCC.db",
                            "apollo_module": "tcc_db"
                        }
                    },
                    {
                        "datetime": "2023-11-14T22:14:00Z",
                        "data": {
                            "client": "com.example.cam",
                            "service": "kTCCServiceMicrophone",
                            "allowed": "NOT ALLOWED",
                            "source_db": "logs/Accessibility/TCC.db",
                            "apollo_module": "tcc_db"
                        }
                    }
                ]
            }),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let v = run(&parsed, &arch);
        assert_eq!(v["app_count"], 1);
        let perms = v["apps"]["com.example.cam"]["permissions"].as_array().unwrap();
        assert_eq!(perms.len(), 2);
        assert_eq!(perms[0]["service"], "kTCCServiceCamera");
    }
}
