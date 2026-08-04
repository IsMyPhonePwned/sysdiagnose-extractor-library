//! Port of SAF `parsers/lockdownd.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    extract_lockdownd, matching_utf8_files, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct LockdowndParser;

impl SysdiagnoseParser for LockdowndParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let tz = sysdiagnose_creation(archive).timezone();
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(archive, &["logs/MobileLockdown/lockdownd.log*"])? {
            events.extend(extract_lockdownd(&text, "lockdownd", tz));
        }
        Ok(wrap_jsonl("lockdownd", events))
    }
}
