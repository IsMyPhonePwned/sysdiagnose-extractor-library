//! APOLLO modules for Apple Knowledge (`knowledgeC.db`) → jsonl-style `events`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct KnowledgecParser;

impl SysdiagnoseParser for KnowledgecParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "knowledgec",
            &[
                "**/Knowledge/knowledgeC.db",
                "**/CoreDuet/Knowledge/knowledgeC.db",
                "**/knowledgeC.db",
                "**/knowledgeC.db-*",
                "logs/**/knowledgeC.db",
            ],
            "knowledgeC.db",
        )
    }
}
