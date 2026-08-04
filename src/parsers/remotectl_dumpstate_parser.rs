//! Port of SAF `parsers/remotectl_dumpstate.py` (structured extract).

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;

pub struct RemotectlDumpstateParser;

impl SysdiagnoseParser for RemotectlDumpstateParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        return Ok(json!({
            "parser": "remotectl_dumpstate",
            "data": crate::parsers::parser_helpers::remotectl_tab(archive),
        }));
    }
}
