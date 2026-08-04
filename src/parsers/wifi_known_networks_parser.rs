//! Port of SAF [`wifi_known_networks.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifi_known_networks.py)
//! — plist JSON under **`files`** (same as upstream `load_plist_file_as_json`) plus timeline **`events`**
//! for each BSS with coordinates (addresses upstream *FIXME convert to timeline*).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    events_from_known_networks_plist, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::parser_helpers::plist_map_patterns;
use crate::parsers::SysdiagnoseParser;

const PATTERNS: &[&str] = &[
    "WiFi/com.apple.wifi.known-networks.plist",
    "**/WiFi/com.apple.wifi.known-networks.plist",
];

pub struct WifiKnownNetworksParser;

impl SysdiagnoseParser for WifiKnownNetworksParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = plist_map_patterns(archive, PATTERNS)?;
        let creation = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        if let Value::Object(m) = &files {
            for (path, root) in m {
                events.extend(events_from_known_networks_plist(path, root, creation));
            }
        }
        let mut out = wrap_jsonl("wifi_known_networks", events);
        if let Some(obj) = out.as_object_mut() {
            obj.insert("files".into(), files);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn events_include_bss_with_coordinates() {
        let plist = json!({
            "net-uuid-1": {
                "SSID": "Cafe",
                "AddedAt": "2020-01-02T12:00:00Z",
                "BSSList": [
                    { "LocationLatitude": 48.85, "LocationLongitude": 2.35, "LocationAccuracy": 10.0 }
                ]
            }
        });
        let creation = chrono::FixedOffset::east_opt(3600)
            .unwrap()
            .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .unwrap();
        let evs = crate::parsers::parser_events::events_from_known_networks_plist(
            "WiFi/x.plist",
            &plist,
            creation,
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["module"], "wifi_known_networks");
        assert_eq!(evs[0]["data"]["ssid"], "Cafe");
        assert_eq!(evs[0]["data"]["latitude"], 48.85);
    }

    #[test]
    fn parser_merges_files_and_wrap_jsonl() {
        let mut m = HashMap::new();
        m.insert(
            "WiFi/com.apple.wifi.known-networks.plist".to_string(),
            Arc::from(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>n1</key><dict><key>SSID</key><string>T</string><key>BSSList</key><array><dict><key>LocationLatitude</key><real>1</real><key>LocationLongitude</key><real>2</real></dict></array></dict></dict></plist>"#.to_vec().into_boxed_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = WifiKnownNetworksParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "wifi_known_networks");
        assert_eq!(v["format"], "jsonl");
        assert!(v["files"].is_object());
        let evs = v["events"].as_array().unwrap();
        assert_eq!(evs.len(), 1);
    }
}
