//! Port of SAF `parsers/mobileactivation.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    extract_multiline_log, matching_utf8_files, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct MobileactivationParser;

impl SysdiagnoseParser for MobileactivationParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let tz = sysdiagnose_creation(archive).timezone();
        let mut events = Vec::new();
        for (_, text) in
            matching_utf8_files(archive, &["logs/MobileActivation/mobileactivationd.log*"])?
        {
            events.extend(extract_multiline_log(&text, "mobileactivation", tz));
        }
        Ok(wrap_jsonl("mobileactivation", events))
    }
}
