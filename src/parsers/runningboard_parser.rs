//! RunningBoard live process / assertion dump.

use serde_json::{json, Map, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::matching_utf8_files;
use crate::parsers::SysdiagnoseParser;

pub struct RunningboardParser;

impl SysdiagnoseParser for RunningboardParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, &["RunningBoard/RunningBoard_state.log"])?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No RunningBoard_state.log present"] }));
        }
        let mut out_files = Map::new();
        let mut domains = std::collections::BTreeSet::new();
        let mut jetsam_bands = std::collections::BTreeSet::new();
        for (path, text) in &files {
            out_files.insert((*path).to_string(), json!(*text));
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("com.apple.") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        domains.insert(format!("com.apple.{name}"));
                    }
                }
                if let Some(idx) = line.find("band:") {
                    let band: String = line[idx + 5..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if !band.is_empty() {
                        jetsam_bands.insert(band);
                    }
                }
            }
        }
        Ok(json!({
            "parser": "runningboard",
            "format": "files",
            "files": out_files,
            "meta": {
                "domain_hints": domains.into_iter().take(500).collect::<Vec<_>>(),
                "jetsam_bands_seen": jetsam_bands.into_iter().collect::<Vec<_>>(),
            }
        }))
    }
}
