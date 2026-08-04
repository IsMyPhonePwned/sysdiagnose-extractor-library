//! APOLLO modules for Launch Services quarantine DB → download origin / data URLs.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct QuarantineEventsParser;

impl SysdiagnoseParser for QuarantineEventsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "quarantine_events",
            &[
                "**/com.apple.LaunchServices.QuarantineEventsV2",
                "**/*QuarantineEventsV2*",
            ],
            "com.apple.LaunchServices.QuarantineEventsV2",
        )
    }
}
