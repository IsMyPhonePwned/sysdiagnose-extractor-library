//! MCState shared profile stub summaries.

use serde_json::{json, Value};

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::{compile_globs, matching_files};
use crate::parsers::MAX_UTF8_FILE;

use super::common::ParsedByParser;

pub fn run(_parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let mut rows = Vec::new();
    let Ok(set) = compile_globs(&["logs/MCState/Shared/profile-*.stub"]) else {
        return json!({
            "analyser": "mcstateshared",
            "rows": [],
            "error": "glob_compile_failed",
        });
    };
    for (path, bytes) in matching_files(archive, &set) {
        if bytes.len() > MAX_UTF8_FILE {
            rows.push(json!({
                "path": path,
                "skipped_oversized": true,
                "size": bytes.len(),
            }));
            continue;
        }
        let s = String::from_utf8_lossy(bytes);
        rows.push(json!({
            "path": path,
            "char_count": s.len(),
            "line_count": s.lines().count(),
            "preview": s.chars().take(400).collect::<String>(),
        }));
    }
    json!({
        "analyser": "mcstateshared",
        "rows": rows,
        "note": "MCState profile stubs are raw text in this crate; upstream SAF flattens PayloadContent into CSV.",
        "saf_comparison": "SAF MCStateSharedProfileAnalyser emits CSV rows with flattened PayloadContent; this JSON lists per-file previews for the same stub inputs."
    })
}
