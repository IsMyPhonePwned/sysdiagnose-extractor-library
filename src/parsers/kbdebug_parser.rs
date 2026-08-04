//! Port of SAF `parsers/kbdebug.py` — [`kbdebug`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/kbdebug.py).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{matching_utf8_files, parse_kbdebug_log, wrap_jsonl};
use crate::parsers::SysdiagnoseParser;

pub struct KbdebugParser;

impl SysdiagnoseParser for KbdebugParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(archive, &["kbdebug.txt"])? {
            events.extend(parse_kbdebug_log(&text, "kbdebug"));
        }
        Ok(wrap_jsonl("kbdebug", events))
    }
}
