//! Port of SAF `parsers/olddsc.py`.

use serde_json::Value;
use std::error::Error;
use std::io::Cursor;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_events::{olddsc_events, sysdiagnose_creation, wrap_jsonl};
use crate::parsers::parser_helpers::MAX_UTF8_FILE;
use crate::parsers::SysdiagnoseParser;

pub struct OlddscParser;

impl SysdiagnoseParser for OlddscParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_files_patterns(archive, &["logs/olddsc/*"])?;
        let ts = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        for (_p, b) in files {
            if b.is_empty() || b.len() > MAX_UTF8_FILE {
                continue;
            }
            if let Ok(v) = plist::from_reader::<_, plist::Value>(Cursor::new(b)) {
                if let Ok(j) = serde_json::to_value(v) {
                    events.extend(olddsc_events(&j, "olddsc", ts));
                }
            }
        }
        Ok(wrap_jsonl("olddsc", events))
    }
}
