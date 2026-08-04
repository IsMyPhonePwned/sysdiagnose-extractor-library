//! Port of SAF `parsers/iodevicetree.py` (IOReg structured tree).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::ioreg_parse_result;
use crate::parsers::SysdiagnoseParser;

pub struct IodevicetreeParser;

impl SysdiagnoseParser for IodevicetreeParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Ok(ioreg_parse_result(
            archive,
            "ioreg/IODeviceTree.txt",
            "iodevicetree",
        ))
    }
}
