//! Shared helpers for Wi‑Fi plist JSON (used by `wifi_known_networks` events and Wi‑Fi geolocation analysers).

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;

pub fn parse_wifi_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|n| Utc.from_utc_datetime(&n))
        })
}

/// Top-level keys under a known-networks plist root (drops keys ending in `.plist`).
pub fn wifi_network_dicts(plist_root: &Value) -> Vec<(String, &Value)> {
    let mut out = Vec::new();
    match plist_root {
        Value::Object(m) => {
            for (k, v) in m {
                if k.ends_with(".plist") {
                    continue;
                }
                out.push((k.clone(), v));
            }
        }
        _ => {}
    }
    out
}

pub fn f64_from_plist(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|i| i as f64))
        .or_else(|| v.as_str()?.parse().ok())
}
