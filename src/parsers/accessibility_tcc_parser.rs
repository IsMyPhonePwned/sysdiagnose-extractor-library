//! Port of SAF `parsers/accessibility_tcc.py` — APOLLO `TCC.db` modules → jsonl-style events.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct AccessibilityTccParser;

impl SysdiagnoseParser for AccessibilityTccParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "accessibility_tcc",
            &["logs/Accessibility/TCC.db"],
            "TCC.db",
        )
    }
}
