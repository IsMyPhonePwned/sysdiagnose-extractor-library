//! Port of SAF `parsers/mobilebackup.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{mobilebackup_events, sysdiagnose_creation, wrap_jsonl};
use crate::parsers::parser_helpers::plist_map_patterns;
use crate::parsers::SysdiagnoseParser;

pub struct MobilebackupParser;

impl SysdiagnoseParser for MobilebackupParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let pl = plist_map_patterns(archive, &["logs/MobileBackup/com.apple.MobileBackup.plist"])?;
        let ts = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        if let Value::Object(m) = pl {
            for (_, v) in m {
                events.extend(mobilebackup_events(&v, "mobilebackup", ts));
            }
        }
        Ok(wrap_jsonl("mobilebackup", events))
    }
}
