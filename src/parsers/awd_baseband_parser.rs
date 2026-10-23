//! Apple Wireless Diagnostics / baseband binary traces (inventory only).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::binary_inventory_result;
use crate::parsers::SysdiagnoseParser;

pub struct AwdBasebandParser;

impl SysdiagnoseParser for AwdBasebandParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        binary_inventory_result(
            archive,
            "awd_baseband",
            &[
                "logs/AWD/*.metriclog",
                "logs/AWD/**",
                "logs/Baseband/**",
                "**/*.istp",
                "**/*.metriclog",
            ],
            200,
        )
    }
}
