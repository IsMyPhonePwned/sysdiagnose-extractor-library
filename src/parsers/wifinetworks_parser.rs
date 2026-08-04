//! Port of SAF [`wifinetworks.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifinetworks.py)
//! — basename-keyed plist/JSON map under **`files`** plus timeline **`events`**.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    events_from_wifinetworks_files, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::parser_helpers::wifinetworks_bundle;
use crate::parsers::SysdiagnoseParser;

pub struct WifinetworksParser;

impl SysdiagnoseParser for WifinetworksParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = wifinetworks_bundle(archive)?;
        let creation = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        if let Value::Object(m) = &files {
            events = events_from_wifinetworks_files(m, creation);
        }
        let mut out = wrap_jsonl("wifinetworks", events);
        if let Some(obj) = out.as_object_mut() {
            obj.insert("files".into(), files);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn basename_keys_and_jsonl() {
        let mut m = HashMap::new();
        m.insert(
            "WiFi/com.apple.wifi.known-networks.plist".to_string(),
            Arc::from(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>n1</key><dict><key>SSID</key><string>T</string></dict></dict></plist>"#
                    .to_vec()
                    .into_boxed_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = WifinetworksParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "wifinetworks");
        assert_eq!(v["format"], "jsonl");
        assert!(v["files"]["com.apple.wifi.known-networks"].is_object());
        assert!(!v["events"].as_array().unwrap().is_empty());
    }
}
