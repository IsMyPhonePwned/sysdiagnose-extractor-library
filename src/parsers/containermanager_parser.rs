//! Port of SAF `parsers/containermanager.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    extract_multiline_log, matching_utf8_files, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct ContainermanagerParser;

impl SysdiagnoseParser for ContainermanagerParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let tz = sysdiagnose_creation(archive).timezone();
        let mut events = Vec::new();
        for (_, text) in matching_utf8_files(
            archive,
            &["logs/MobileContainerManager/containermanagerd.log*"],
        )? {
            events.extend(extract_multiline_log(&text, "containermanager", tz));
        }
        Ok(wrap_jsonl("containermanager", events))
    }
}
