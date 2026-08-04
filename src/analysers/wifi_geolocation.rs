//! GPX output from known Wi‑Fi network geolocation data.

use chrono::{TimeZone, Utc};
use serde_json::{json, Value};

use crate::archive::SysdiagnoseArchive;
use crate::parsers::ParserType;

use crate::parsers::{f64_from_plist, parse_wifi_timestamp, wifi_network_dicts};

use super::common::{get_or_parse, xml_escape, ParsedByParser};

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let w = get_or_parse(archive, parsed, ParserType::wifi_known_networks);
    let mut wpts = String::new();
    let paths_ref = match &w {
        Value::Object(o)
            if o.get("parser").and_then(|p| p.as_str()) == Some("wifi_known_networks") =>
        {
            o.get("files").and_then(|v| v.as_object())
        }
        Value::Object(o) => Some(o),
        _ => None,
    };
    if let Some(paths) = paths_ref {
        for (_path, plist_val) in paths {
            for (net_key, network) in wifi_network_dicts(plist_val) {
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
                let ts = parse_wifi_timestamp(ts_str)
                    .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap_or_else(Utc::now));
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
                    let (Some(lat), Some(lon)) = (lat, lon) else {
                        continue;
                    };
                    let acc = bss
                        .get("LocationAccuracy")
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    let desc = format!(
                        "BSSID: {bssid}\nChannel: {channel}\nTimestamp: {ts_str}\nAccuracy: {acc}\nReason: {add_reason}"
                    );
                    wpts.push_str(&format!(
                        r#"  <wpt lat="{lat}" lon="{lon}">
    <name>{}</name>
    <desc>{}</desc>
    <time>{}</time>
  </wpt>
"#,
                        xml_escape(ssid),
                        xml_escape(&desc),
                        ts.format("%Y-%m-%dT%H:%M:%SZ")
                    ));
                }
            }
        }
    }
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="sysdiagnose-extractor-library" xmlns="http://www.topografix.com/GPX/1/1">
{wpts}</gpx>
"#
    );
    json!({
        "analyser": "wifi_geolocation",
        "format": "gpx",
        "xml": xml,
    })
}
