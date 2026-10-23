//! `microstackshots` process-sampling history (gzip-wrapped binary).

use flate2::read::GzDecoder;
use serde_json::{json, Value};
use std::error::Error;
use std::io::Read;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::SysdiagnoseParser;

pub struct MicrostackshotsParser;

impl SysdiagnoseParser for MicrostackshotsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_files_patterns(archive, &["microstackshots", "**/microstackshots"])
            .map_err(|e| e.to_string())?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No microstackshots member present"] }));
        }
        let mut entries = Vec::new();
        for (path, bytes) in files {
            let gzip = bytes.starts_with(&[0x1f, 0x8b]);
            let mut decompressed_size = None;
            let mut decode_error = None;
            if gzip {
                let mut dec = GzDecoder::new(std::io::Cursor::new(bytes));
                let mut out = Vec::new();
                // Cap inflate to avoid huge allocations.
                let mut limited = (&mut dec).take(64 * 1024 * 1024);
                match limited.read_to_end(&mut out) {
                    Ok(_) => decompressed_size = Some(out.len()),
                    Err(e) => decode_error = Some(e.to_string()),
                }
            }
            entries.push(json!({
                "path": path,
                "compressed_size": bytes.len(),
                "gzip": gzip,
                "decompressed_size": decompressed_size,
                "decode_error": decode_error,
            }));
        }
        Ok(json!({
            "parser": "microstackshots",
            "format": "inventory",
            "files": entries,
            "note": "Binary process-sampling history; full decode not implemented",
        }))
    }
}
