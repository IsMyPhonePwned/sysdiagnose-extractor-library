//! CloudKit Key Sync (`ckksctl_status`) and Protected Cloud Storage (`pcsstatus`).

use serde_json::{json, Map, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::matching_utf8_files;
use crate::parsers::SysdiagnoseParser;

pub struct CkksPcsParser;

impl SysdiagnoseParser for CkksPcsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(
            archive,
            &["ckksctl_status.txt", "pcsstatus.txt", "**/ckksctl_status.txt", "**/pcsstatus.txt"],
        )?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No ckksctl_status.txt / pcsstatus.txt present"] }));
        }
        let mut out = Map::new();
        for (path, text) in files {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                out.insert(path.to_string(), json!({ "empty": true }));
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                out.insert(path.to_string(), v);
            } else {
                out.insert(path.to_string(), json!({ "raw": text }));
            }
        }
        Ok(json!({
            "parser": "ckks_pcs",
            "format": "files",
            "files": out,
        }))
    }
}
