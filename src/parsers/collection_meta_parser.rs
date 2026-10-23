//! Sysdiagnose collection metadata: `taskSummary.csv`, `errors/`, `summaries/`, `sysdiagnose.log`.

use serde_json::{json, Map, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_events::matching_utf8_files;
use crate::parsers::parser_helpers::MAX_UTF8_FILE;
use crate::parsers::SysdiagnoseParser;

const MAX_SUMMARY_FILES: usize = 80;
const MAX_SUMMARY_CHARS: usize = 8_192;

pub struct CollectionMetaParser;

impl SysdiagnoseParser for CollectionMetaParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut task_rows = Vec::new();
        for (_, text) in matching_utf8_files(archive, &["taskSummary.csv"])? {
            // Lines look CSV-ish but include section headers; keep command rows.
            for line in text.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with("Concurrent group") {
                    continue;
                }
                if t.starts_with("Command,") {
                    continue;
                }
                if t.starts_with('"') || t.contains("exited with") {
                    task_rows.push(json!({ "raw": t }));
                }
            }
        }

        let mut errors = Map::new();
        for (path, text) in matching_utf8_files(archive, &["errors/*.txt", "**/errors/*.txt"])? {
            errors.insert(path.to_string(), json!(text));
        }

        let mut summaries = Map::new();
        let mut summary_files =
            matching_files_patterns(archive, &["summaries/*.log", "**/summaries/*.log"])
                .map_err(|e| e.to_string())?;
        summary_files.sort_by_key(|(p, _)| *p);
        let summary_total = summary_files.len();
        if summary_files.len() > MAX_SUMMARY_FILES {
            summary_files.truncate(MAX_SUMMARY_FILES);
        }
        for (path, bytes) in summary_files {
            if bytes.len() > MAX_UTF8_FILE {
                summaries.insert(
                    path.to_string(),
                    json!({ "skipped_oversized": true, "size": bytes.len() }),
                );
                continue;
            }
            let text = String::from_utf8_lossy(bytes);
            let preview: String = text.chars().take(MAX_SUMMARY_CHARS).collect();
            summaries.insert(
                path.to_string(),
                json!({
                    "preview": preview,
                    "len": text.len(),
                    "truncated": text.len() > MAX_SUMMARY_CHARS,
                }),
            );
        }

        let mut sysdiagnose_log = Value::Null;
        if let Some((_, bytes)) = archive.find_suffix("sysdiagnose.log") {
            if bytes.len() <= MAX_UTF8_FILE {
                let text = String::from_utf8_lossy(bytes);
                let preview: String = text.chars().take(64_000).collect();
                sysdiagnose_log = json!({
                    "preview": preview,
                    "len": text.len(),
                });
            } else {
                sysdiagnose_log = json!({ "skipped_oversized": true, "size": bytes.len() });
            }
        }

        Ok(json!({
            "parser": "collection_meta",
            "format": "structured",
            "task_summary": task_rows,
            "errors": errors,
            "summaries": summaries,
            "sysdiagnose_log": sysdiagnose_log,
            "meta": {
                "summary_total_matched": summary_total,
                "summary_returned": summaries.len(),
                "error_file_count": errors.len(),
                "note": "Use errors/ + task_summary to explain empty parser outputs",
            }
        }))
    }
}
