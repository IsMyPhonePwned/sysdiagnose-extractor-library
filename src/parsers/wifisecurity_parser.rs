//! Port of SAF `parsers/wifisecurity.py`.

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{matching_utf8_files, parse_wifi_security, wrap_jsonl};
use crate::parsers::SysdiagnoseParser;

pub struct WifisecurityParser;

impl SysdiagnoseParser for WifisecurityParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, &["WiFi/security.txt"])?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No WiFi/security.txt file present"] }));
        }
        let mut events = Vec::new();
        for (_, text) in files {
            events.extend(parse_wifi_security(&text, "wifisecurity"));
        }
        Ok(wrap_jsonl("wifisecurity", events))
    }
}
