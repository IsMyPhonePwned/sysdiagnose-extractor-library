//! OTA / restore logs (`restore_perform`, patches, tolerated failures).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::text_files_result;
use crate::parsers::SysdiagnoseParser;

pub struct OtaUpdateParser;

impl SysdiagnoseParser for OtaUpdateParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        text_files_result(
            archive,
            "ota_update",
            &[
                "logs/OTAUpdateLogs/restore_perform.txt",
                "logs/OTAUpdateLogs/*.txt",
                "logs/OTAUpdateLogs/*.ips",
                "logs/OTAUpdateLogs/*.plist",
            ],
            64,
        )
    }
}
