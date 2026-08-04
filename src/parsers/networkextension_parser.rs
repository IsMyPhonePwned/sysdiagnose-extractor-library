//! Port of SAF `parsers/networkextension.py` (structured extract).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;

pub struct NetworkextensionParser;

impl SysdiagnoseParser for NetworkextensionParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        crate::parsers::parser_helpers::plist_map_patterns(
            archive,
            &["logs/Networking/com.apple.networkextension.plist"],
        )
    }
}
