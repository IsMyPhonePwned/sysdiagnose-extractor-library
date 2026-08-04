//! Port of SAF `parsers/iopower.py` (IOReg structured tree).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::ioreg_parse_result;
use crate::parsers::SysdiagnoseParser;

pub struct IopowerParser;

impl SysdiagnoseParser for IopowerParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Ok(ioreg_parse_result(archive, "ioreg/IOPower.txt", "iopower"))
    }
}
