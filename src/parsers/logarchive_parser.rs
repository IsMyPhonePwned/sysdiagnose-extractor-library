//! Port of SAF [`logarchive.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/logarchive.py).
//!
//! Unified log **decode** uses `macos-unifiedlogs` via the `logarchive-decode` feature.

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::logarchive_decode::decode_logarchive_events_with_limit;
use crate::parsers::{ParseOptions, SysdiagnoseParser};

pub struct LogarchiveParser;

impl LogarchiveParser {
    pub fn parse_with_options(
        &self,
        archive: &SysdiagnoseArchive,
        options: &ParseOptions,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let inventory = crate::parsers::parser_helpers::prefix_inventory(
            archive,
            "system_logs.logarchive/",
        );

        if options.logarchive_inventory_only {
            return Ok(json!({
                "parser": "logarchive",
                "inventory": inventory,
                "decode": "deferred",
                "decode_meta": {
                    "status": "deferred",
                    "reason": "inventory_only (decode runs once after other parsers)",
                },
                "note": "Inventory only — host will decode unified logs in a later pass.",
            }));
        }

        let (decode_meta, events) =
            decode_logarchive_events_with_limit(archive, options.logarchive_decode_max_lines);
        let status = decode_meta
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        let mut out = json!({
            "parser": "logarchive",
            "inventory": inventory,
            "decode": status,
            "decode_meta": decode_meta,
            "note": "Unified log decode via logarchive-decode feature (macos-unifiedlogs). See docs/logarchive.md.",
        });

        if status == "success" {
            out["format"] = json!("jsonl");
            out["events"] = json!(events);
        }

        Ok(out)
    }
}

impl SysdiagnoseParser for LogarchiveParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        self.parse_with_options(archive, &ParseOptions::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn inventory_lists_logarchive_paths() {
        let mut m = HashMap::new();
        m.insert(
            "system_logs.logarchive/Info.plist".into(),
            Arc::from(b"plist".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = LogarchiveParser.parse(&arch).unwrap();
        assert_eq!(v["inventory"]["file_count"], 1);
        assert_eq!(v["inventory"]["paths"].as_array().unwrap().len(), 1);
        #[cfg(not(feature = "logarchive-decode"))]
        assert_eq!(v["decode"], "deferred");
        #[cfg(feature = "logarchive-decode")]
        assert_eq!(v["decode"], "skipped");
    }
}
