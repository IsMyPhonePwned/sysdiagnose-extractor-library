//! Port of SAF `parsers/disks.py`.

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_disks_txt, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct DisksParser;

impl SysdiagnoseParser for DisksParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, &["disks.txt"])?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No disks.txt file present"] }));
        }
        let ts = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        for (_, text) in files {
            events.extend(parse_disks_txt(&text, "disks", ts));
        }
        Ok(wrap_jsonl("disks", events))
    }
}
