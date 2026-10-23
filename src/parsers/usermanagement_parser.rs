//! User accounts / personas (`umtool`, `usermanagerd`).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::text_files_result;
use crate::parsers::SysdiagnoseParser;

pub struct UsermanagementParser;

impl SysdiagnoseParser for UsermanagementParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        text_files_result(
            archive,
            "usermanagement",
            &[
                "logs/umtool/umtool.txt",
                "logs/umtool/**",
                "logs/UserManagement/umtool.txt",
                "logs/UserManagement/usermanagerd.log*",
                "**/usermanagerd.log*",
            ],
            32,
        )
    }
}
