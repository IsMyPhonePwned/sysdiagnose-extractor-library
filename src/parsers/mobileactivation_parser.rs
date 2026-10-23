//! Port of SAF `parsers/mobileactivation.py`, plus DCRT/BAA attestation text dumps.

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    extract_multiline_log, matching_utf8_files, saf_event_dict, sysdiagnose_creation, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

pub struct MobileactivationParser;

impl SysdiagnoseParser for MobileactivationParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let created = sysdiagnose_creation(archive);
        let tz = created.timezone();
        let mut events = Vec::new();
        for (path, text) in matching_utf8_files(
            archive,
            &[
                "logs/MobileActivation/mobileactivationd.log*",
                "logs/MobileActivation/mobileactivationd_dcrt_baa_*.txt",
            ],
        )? {
            let base = path.rsplit('/').next().unwrap_or(path.as_str());
            if base.contains("dcrt_baa") {
                let kind = if base.contains("request") {
                    "dcrt_baa_request"
                } else if base.contains("response") {
                    "dcrt_baa_response"
                } else {
                    "dcrt_baa"
                };
                let preview: String = text.chars().take(16_384).collect();
                events.push(saf_event_dict(
                    "mobileactivation",
                    created,
                    kind,
                    &format!("{kind} ({path})"),
                    json!({
                        "source_path": path,
                        "kind": kind,
                        "content": preview,
                        "content_len": text.len(),
                    }),
                ));
            } else {
                events.extend(extract_multiline_log(&text, "mobileactivation", tz));
            }
        }
        Ok(wrap_jsonl("mobileactivation", events))
    }
}
