//! Port of SAF `parsers/wifiscan.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_wifi_scan, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct WifiscanParser;

impl SysdiagnoseParser for WifiscanParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let ts = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(archive, &["WiFi/wifi_scan*.txt"])? {
            events.extend(parse_wifi_scan(&text, "wifiscan", ts));
        }
        Ok(wrap_jsonl("wifiscan", events))
    }
}
