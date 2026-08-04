//! Port of SAF `parsers/powerlogs.py` — APOLLO `CurrentPowerlog.PLSQL` modules → jsonl-style events.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct PowerlogsParser;

impl SysdiagnoseParser for PowerlogsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "powerlogs",
            &["logs/powerlogs/powerlog_*", "logs/powerlogs/log_*"],
            "CurrentPowerlog.PLSQL",
        )
    }
}
