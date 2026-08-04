//! Port of SAF `parsers/avconference_callsettings.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_events::{decompress_gzip, parse_avconference_gzip, wrap_jsonl};
use crate::parsers::SysdiagnoseParser;

pub struct AvconferenceCallsettingsParser;

impl SysdiagnoseParser for AvconferenceCallsettingsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files =
            matching_files_patterns(archive, &["logs/AVConference/*-CallSettings.calldump.gz"])?;
        let mut events = Vec::new();
        for (p, b) in files {
            if b.is_empty() {
                continue;
            }
            let raw =
                decompress_gzip(b).map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;
            match parse_avconference_gzip(p, &raw, "avconference_callsettings") {
                Ok(mut e) => events.append(&mut e),
                Err(_) => continue,
            }
        }
        Ok(wrap_jsonl("avconference_callsettings", events))
    }
}
