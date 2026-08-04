//! Port of SAF `parsers/logdata_statistics_txt.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_logdata_statistics_txt, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct LogdataStatisticsTxtParser;

impl SysdiagnoseParser for LogdataStatisticsTxtParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(
            archive,
            &["system_logs.logarchive/Extra/logdata.statistics.*.txt"],
        )? {
            events.extend(parse_logdata_statistics_txt(
                &text,
                "logdata_statistics_txt",
            ));
        }
        Ok(wrap_jsonl("logdata_statistics_txt", events))
    }
}
