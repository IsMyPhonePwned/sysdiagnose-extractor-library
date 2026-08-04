//! Port of SAF `parsers/logdata_statistics.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_logdata_statistics_jsonl, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct LogdataStatisticsParser;

impl SysdiagnoseParser for LogdataStatisticsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(
            archive,
            &["system_logs.logarchive/Extra/logdata.statistics.*.jsonl"],
        )? {
            events.extend(parse_logdata_statistics_jsonl(&text, "logdata_statistics"));
        }
        Ok(wrap_jsonl("logdata_statistics", events))
    }
}
