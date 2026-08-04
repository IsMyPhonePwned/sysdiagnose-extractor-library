//! Timeline **`events`** for [`wifinetworks.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifinetworks.py)
//! (upstream plist/json map only; *FIXME convert to timeline*).

use chrono::FixedOffset;
use serde_json::{json, Map, Value};

use super::common::saf_event_dict;
use super::wifi::{f64_from_plist, parse_wifi_timestamp, wifi_network_dicts};

const MODULE: &str = "wifinetworks";

pub fn events_from_wifinetworks_files(
    files: &Map<String, Value>,
    fallback_time: chrono::DateTime<FixedOffset>,
) -> Vec<Value> {
    let mut out = Vec::new();
    for (file_key, root) in files {
        if root.as_object().is_some_and(|o| o.contains_key("error")) {
            continue;
        }
        if file_key.ends_with(".json") {
            out.push(saf_event_dict(
                MODULE,
                fallback_time,
                "Wi-Fi recent networks JSON",
                &format!("WiFi file {file_key}"),
                json!({ "file": file_key, "payload": root }),
            ));
            continue;
        }
        for (net_key, network) in wifi_network_dicts(root) {
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
            let data = json!({
                "file": file_key,
                "network_key": net_key,
                "ssid": ssid,
                "timestamp_raw": ts_str,
                "network": net,
            });
            let msg = format!("WiFi network {ssid} ({file_key}/{net_key})");
            out.push(saf_event_dict(
                MODULE,
                ts_fixed,
                "Wi-Fi plist network entry",
                &msg,
                data,
            ));

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
                let coord_data = json!({
                    "file": file_key,
                    "network_key": net_key,
                    "ssid": ssid,
                    "latitude": lat,
                    "longitude": lon,
                    "bss": bss,
                });
                out.push(saf_event_dict(
                    MODULE,
                    ts_fixed,
                    "Wi-Fi BSS location",
                    &format!("WiFi BSS location {ssid} ({file_key})"),
                    coord_data,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn emits_network_and_bss_events() {
        let mut files = Map::new();
        files.insert(
            "com.apple.wifi.known-networks".into(),
            json!({
                "n1": {
                    "SSID": "Cafe",
                    "AddedAt": "2020-01-02T12:00:00Z",
                    "BSSList": [{"LocationLatitude": 1.0, "LocationLongitude": 2.0}]
                }
            }),
        );
        let t = chrono::FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .unwrap();
        let evs = events_from_wifinetworks_files(&files, t);
        assert_eq!(evs.len(), 2);
    }
}
