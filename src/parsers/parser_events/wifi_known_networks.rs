//! Timeline-style **`events`** from [`com.apple.wifi.known-networks.plist`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifi_known_networks.py)
//! (upstream still returns plist JSON only; SAF comment *FIXME convert to timeline*).

use chrono::{DateTime, FixedOffset};
use serde_json::{json, Value};

use super::common::saf_event_dict;
use super::wifi::{f64_from_plist, parse_wifi_timestamp, wifi_network_dicts};

const MODULE: &str = "wifi_known_networks";

/// One event per BSS row that has coordinates (same coverage as `wifi_geolocation` / `wifi_geolocation_kml`).
pub fn events_from_known_networks_plist(
    plist_rel_path: &str,
    plist_root: &Value,
    fallback_time: DateTime<FixedOffset>,
) -> Vec<Value> {
    if plist_root
        .as_object()
        .is_some_and(|o| o.contains_key("error"))
    {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (net_key, network) in wifi_network_dicts(plist_root) {
        let Value::Object(net) = network else {
            continue;
        };
        let ssid = net
            .get("SSID")
            .and_then(|v| v.as_str())
            .unwrap_or(net_key.as_str());
        let ts_str = net
            .get("AddedAt")
            .or_else(|| net.get("JoinedByUserAt"))
            .or_else(|| net.get("UpdatedAt"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ts_fixed = parse_wifi_timestamp(ts_str)
            .map(|u| u.with_timezone(&FixedOffset::east_opt(0).unwrap()))
            .unwrap_or(fallback_time);

        let bssid = net
            .get("__OSSpecific__")
            .and_then(|o| o.get("BSSID"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let channel = net
            .get("__OSSpecific__")
            .and_then(|o| o.get("CHANNEL"))
            .map(|v| v.to_string())
            .unwrap_or_default();
        let add_reason = net.get("AddReason").and_then(|v| v.as_str()).unwrap_or("");
        let bss_list = net
            .get("BSSList")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for bss in bss_list {
            let lat = f64_from_plist(bss.get("LocationLatitude").unwrap_or(&Value::Null));
            let lon = f64_from_plist(bss.get("LocationLongitude").unwrap_or(&Value::Null));
            if lat.is_none() || lon.is_none() {
                continue;
            }
            let acc = bss
                .get("LocationAccuracy")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let data = json!({
                "plist_path": plist_rel_path,
                "network_key": net_key,
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "add_reason": add_reason,
                "timestamp_raw": ts_str,
                "latitude": lat,
                "longitude": lon,
                "accuracy": acc,
                "bss": bss,
            });
            let msg = format!("WiFi BSS location {ssid} ({net_key})");
            out.push(saf_event_dict(
                MODULE,
                ts_fixed,
                "known Wi-Fi network BSS location",
                &msg,
                data,
            ));
        }
    }
    out
}
