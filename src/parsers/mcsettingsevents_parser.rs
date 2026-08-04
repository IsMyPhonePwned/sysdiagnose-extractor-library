//! Port of SAF `parsers/mcsettingsevents.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{mc_settings_events, wrap_jsonl};
use crate::parsers::parser_helpers::plist_map_patterns;
use crate::parsers::SysdiagnoseParser;

pub struct McsettingseventsParser;

impl SysdiagnoseParser for McsettingseventsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let pl = plist_map_patterns(archive, &["logs/MCState/Shared/MCSettingsEvents.plist"])?;
        let mut events = Vec::new();
        if let Value::Object(m) = pl {
            for (_, v) in m {
                events.extend(mc_settings_events(&v, "mcsettingsevents"));
            }
        }
        Ok(wrap_jsonl("mcsettingsevents", events))
    }
}
