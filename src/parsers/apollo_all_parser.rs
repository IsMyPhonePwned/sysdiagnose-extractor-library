//! Run all bundled APOLLO modules against every matching SQLite file in the archive.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::apollo::parse_apollo_all_archives;
use crate::parsers::SysdiagnoseParser;

pub struct ApolloAllParser;

impl SysdiagnoseParser for ApolloAllParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        parse_apollo_all_archives(archive)
    }
}
