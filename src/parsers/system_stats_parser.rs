//! Low-forensic-value system statistics text dumps (APFS, VM, SMC, Trial, …).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::text_files_result;
use crate::parsers::SysdiagnoseParser;

pub struct SystemStatsParser;

impl SysdiagnoseParser for SystemStatsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        text_files_result(
            archive,
            "system_stats",
            &[
                "apfs_stats.txt",
                "vm_stat.txt",
                "zprint.txt",
                "codecctl.txt",
                "smcDiagnose.txt",
                "night-shift.log",
                "ASPSnapshots/*",
                "logs/Trial/trial.log",
                "logs/suggest_tool/*",
                "TimezoneDB/*",
            ],
            128,
        )
    }
}
