//! Port of SAF `parsers/appinstallation.py`.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{appinstallation_events_from_tables, wrap_jsonl};
use crate::parsers::parser_helpers::sqlite_map;
use crate::parsers::SysdiagnoseParser;

pub struct AppinstallationParser;

impl SysdiagnoseParser for AppinstallationParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let sm = sqlite_map(
            archive,
            &[
                "logs/appinstallation/AppUpdates.sqlitedb",
                "logs/appinstallation/appstored.sqlitedb",
            ],
        )?;
        let mut events = Vec::new();
        if let Value::Object(root) = sm {
            for (_, db_val) in root {
                events.extend(appinstallation_events_from_tables(
                    &db_val,
                    "appinstallation",
                ));
            }
        }
        Ok(wrap_jsonl("appinstallation", events))
    }
}
