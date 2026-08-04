//! Port of SAF `parsers/battery_bdc.py`.

use serde_json::Value;
use std::error::Error;
use std::path::Path;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_events::{parse_battery_bdc_csv, wrap_jsonl};
use crate::parsers::parser_helpers::MAX_UTF8_FILE;
use crate::parsers::SysdiagnoseParser;

pub struct BatteryBdcParser;

impl SysdiagnoseParser for BatteryBdcParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_files_patterns(archive, &["logs/BatteryBDC/*.csv"])?;
        let mut events = Vec::new();
        for (p, b) in files {
            if b.is_empty() {
                continue;
            }
            if Path::new(p)
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                continue;
            }
            if b.len() > MAX_UTF8_FILE {
                continue;
            }
            let text = String::from_utf8_lossy(b);
            let stem = Path::new(p)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let entry_type = stem.rsplitn(3, '_').last().unwrap_or(stem);
            events.extend(parse_battery_bdc_csv(&text, "battery_bdc", entry_type)?);
        }
        Ok(wrap_jsonl("battery_bdc", events))
    }
}
