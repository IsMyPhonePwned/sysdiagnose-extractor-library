//! Port of SAF `parsers/security_sysdiagnose.py` — jsonl-style `events`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_security_sysdiagnose, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct SecuritySysdiagnoseParser;

impl SysdiagnoseParser for SecuritySysdiagnoseParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, &["security-sysdiagnose.txt"])?;
        let Some((_, text)) = files.first() else {
            return Ok(wrap_jsonl("security_sysdiagnose", vec![]));
        };
        let creation = sysdiagnose_creation(archive);
        let events = parse_security_sysdiagnose(text, creation);
        Ok(wrap_jsonl("security_sysdiagnose", events))
    }
}
