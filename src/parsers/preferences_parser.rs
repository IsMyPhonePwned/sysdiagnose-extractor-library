//! Sysdiagnose `Preferences/*.txt` dumps (locale, Screen Time, accessibility, …).

use serde_json::{json, Map, Value};
use std::error::Error;
use std::io::Cursor;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_helpers::MAX_UTF8_FILE;
use crate::parsers::SysdiagnoseParser;

pub struct PreferencesParser;

impl SysdiagnoseParser for PreferencesParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut files =
            matching_files_patterns(archive, &["Preferences/*.txt", "**/Preferences/*.txt"])
                .map_err(|e| e.to_string())?;
        files.sort_by_key(|(p, _)| *p);
        let total = files.len();
        if files.len() > 200 {
            files.truncate(200);
        }
        let mut out = Map::new();
        for (path, bytes) in files {
            if bytes.len() > MAX_UTF8_FILE {
                out.insert(
                    path.to_string(),
                    json!({ "skipped_oversized": true, "size": bytes.len() }),
                );
                continue;
            }
            let text = String::from_utf8_lossy(bytes);
            // Prefer structured parse of OpenStep / XML plist text; fall back to raw.
            let parsed = plist::from_reader::<_, plist::Value>(Cursor::new(bytes))
                .ok()
                .and_then(|v| serde_json::to_value(v).ok());
            out.insert(
                path.to_string(),
                match parsed {
                    Some(v) => json!({ "plist": v, "raw": text.as_ref() }),
                    None => json!({ "raw": text.as_ref() }),
                },
            );
        }
        Ok(json!({
            "parser": "preferences",
            "format": "files",
            "files": out,
            "meta": { "total_matched": total, "returned": out.len() },
        }))
    }
}
