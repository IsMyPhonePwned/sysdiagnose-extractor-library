//! APOLLO modules for Screen Time (`RMAdminStore-*.sqlite`) → domains / usage events.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_archives;
use crate::parsers::parser_events::wrap_jsonl;
use crate::parsers::SysdiagnoseParser;

pub struct ScreentimeParser;

impl SysdiagnoseParser for ScreentimeParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut all_events = Vec::new();
        for (db_type, patterns) in [
            (
                "RMAdminStore-Local.sqlite",
                &["**/RMAdminStore-Local.sqlite", "**/ScreenTime/RMAdminStore-Local.sqlite"][..],
            ),
            (
                "RMAdminStore-Cloud.sqlite",
                &["**/RMAdminStore-Cloud.sqlite", "**/ScreenTime/RMAdminStore-Cloud.sqlite"][..],
            ),
        ] {
            let v = parse_apollo_archives(archive, "screentime", patterns, db_type)?;
            if let Some(evs) = v.get("events").and_then(|e| e.as_array()) {
                all_events.extend(evs.iter().cloned());
            }
        }
        Ok(wrap_jsonl("screentime", all_events))
    }
}
