//! APOLLO modules for `interactionC.db` → contact interaction URLs / domains.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct InteractioncParser;

impl SysdiagnoseParser for InteractioncParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "interactionc",
            &["**/interactionC.db", "**/CoreDuet/interactionC.db"],
            "interactionC.db",
        )
    }
}
