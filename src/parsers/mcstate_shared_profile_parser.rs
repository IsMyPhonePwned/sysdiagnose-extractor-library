//! Port of SAF `parsers/mcstate_shared_profile.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{mcstate_shared_profile_events, wrap_jsonl};
use crate::parsers::parser_helpers::plist_map_patterns;
use crate::parsers::SysdiagnoseParser;

pub struct McstateSharedProfileParser;

impl SysdiagnoseParser for McstateSharedProfileParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let pl = plist_map_patterns(archive, &["logs/MCState/Shared/profile-*.stub"])?;
        let mut events = Vec::new();
        if let Value::Object(m) = pl {
            for (_, v) in m {
                if let Some(ev) = mcstate_shared_profile_events(&v, "mcstate_shared_profile") {
                    events.extend(ev);
                }
            }
        }
        Ok(wrap_jsonl("mcstate_shared_profile", events))
    }
}
