//! Parser coverage summary (JSON) vs SAF HTML coverage report.

use serde_json::{json, Value};
use std::collections::HashSet;

use crate::archive::SysdiagnoseArchive;

use super::common::ParsedByParser;

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let defined: Vec<_> = crate::all_parser_types()
        .into_iter()
        .map(|p| p.as_str().to_string())
        .collect();
    let defined_set: HashSet<_> = defined.iter().cloned().collect();
    let present: HashSet<_> = parsed.keys().cloned().collect();
    let mut not_in_run: Vec<_> = defined_set.difference(&present).cloned().collect();
    not_in_run.sort();
    let mut present_sorted: Vec<_> = present.into_iter().collect();
    present_sorted.sort();
    json!({
        "analyser": "coverage",
        "parser_types_total": defined.len(),
        "parsed_keys_count": parsed.len(),
        "parser_keys_present": present_sorted,
        "parser_types_not_in_map": not_in_run,
        "archive_file_count": archive.len(),
        "saf_comparison": "SAF CoverageAnalyser walks the case directory, assigns each file to a parser via get_log_files(), and emits HTML (python-magic MIME). This JSON reports which parser IDs appear in the current parsed map plus archive file count — use it when the library run is the source of truth."
    })
}
