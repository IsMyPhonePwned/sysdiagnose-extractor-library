//! Port of SAF `parsers/transparency.py` (whole JSON `transparency.log`, not JSONL).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{matching_utf8_files, transparency_extract_events, wrap_jsonl};
use crate::parsers::SysdiagnoseParser;

pub struct TransparencyParser;

impl SysdiagnoseParser for TransparencyParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(archive, &["transparency.log"])? {
            if let Ok(root) = serde_json::from_str::<Value>(&text) {
                events.extend(transparency_extract_events(&root, "transparency"));
            }
        }
        Ok(wrap_jsonl("transparency", events))
    }
}
