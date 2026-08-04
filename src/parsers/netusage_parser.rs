//! APOLLO modules for `netusage.sqlite` → jsonl-style `events` (per-process / route usage).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::SysdiagnoseParser;

pub struct NetusageParser;

impl SysdiagnoseParser for NetusageParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_archives(
            archive,
            "netusage",
            &[
                "**/netusage.sqlite",
                "logs/Networking/netusage.sqlite",
                "**/Networking/netusage.sqlite",
            ],
            "netusage.sqlite",
        )
    }
}
