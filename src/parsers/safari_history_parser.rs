//! APOLLO modules for Safari `History.db` → jsonl-style `events` (URLs, visit times).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct SafariHistoryParser;

impl SysdiagnoseParser for SafariHistoryParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "safari_history",
            &["**/Safari/History.db", "**/History.db"],
            "History.db",
        )
    }
}
