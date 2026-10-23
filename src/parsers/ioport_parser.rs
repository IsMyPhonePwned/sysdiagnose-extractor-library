//! IOPort.txt via the shared IOReg structured tree parser (not in upstream SAF).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::ioreg_parse_result;
use crate::parsers::SysdiagnoseParser;

pub struct IoportParser;

impl SysdiagnoseParser for IoportParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Ok(ioreg_parse_result(archive, "ioreg/IOPort.txt", "ioport"))
    }
}
