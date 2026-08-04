//! Port of SAF [`swcutil.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/swcutil.py)
//! — jsonl **`events`** via [`wrap_jsonl`](crate::parsers::parser_events::wrap_jsonl).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_swcutil_show, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

const SWCUTIL_PATTERNS: &[&str] = &["**/swcutil_show.txt"];

pub struct SwcutilParser;

impl SysdiagnoseParser for SwcutilParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, SWCUTIL_PATTERNS)?;
        if files.is_empty() {
            return Ok(wrap_jsonl("swcutil", vec![]));
        }
        let creation = sysdiagnose_creation(archive);
        let mut events = Vec::new();
        for (_path, text) in files {
            events.extend(parse_swcutil_show(&text, creation));
        }
        Ok(wrap_jsonl("swcutil", events))
    }
}
