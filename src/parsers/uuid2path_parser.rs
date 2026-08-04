//! Port of SAF `parsers/uuid2path.py` (structured extract).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;

pub struct Uuid2pathParser;

impl SysdiagnoseParser for Uuid2pathParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        crate::parsers::parser_helpers::plist_map_patterns(
            archive,
            &["logs/tailspindb/UUIDToBinaryLocations"],
        )
    }
}
