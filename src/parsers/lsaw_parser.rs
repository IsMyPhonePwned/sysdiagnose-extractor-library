//! LaunchServices `lsaw.csstoredump` — gzip-wrapped binary store (best-effort strings).

use flate2::read::GzDecoder;
use serde_json::{json, Value};
use std::error::Error;
use std::io::Read;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_helpers::extract_lsaw_strings;
use crate::parsers::SysdiagnoseParser;

const MAX_INFLATE: u64 = 64 * 1024 * 1024;

pub struct LsawParser;

impl SysdiagnoseParser for LsawParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_files_patterns(archive, &["lsaw.csstoredump", "**/lsaw.csstoredump"])
            .map_err(|e| e.to_string())?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No lsaw.csstoredump present"] }));
        }
        let (path, bytes) = files[0];
        let gzip = bytes.starts_with(&[0x1f, 0x8b]);
        let mut body = bytes.to_vec();
        let mut inflate_error = None;
        if gzip {
            let mut dec = GzDecoder::new(std::io::Cursor::new(bytes));
            let mut out = Vec::new();
            let mut limited = (&mut dec).take(MAX_INFLATE);
            match limited.read_to_end(&mut out) {
                Ok(_) => body = out,
                Err(e) => {
                    inflate_error = Some(e.to_string());
                    body.clear();
                }
            }
        }
        let strings = if body.is_empty() {
            json!({ "urls": [], "bundle_id_hints": [], "note": "decode failed" })
        } else {
            extract_lsaw_strings(&body, 2_000, 2_000)
        };
        Ok(json!({
            "parser": "lsaw",
            "format": "csstore_strings",
            "source_path": path,
            "compressed_size": bytes.len(),
            "gzip": gzip,
            "decompressed_size": if inflate_error.is_none() { Some(body.len()) } else { None },
            "inflate_error": inflate_error,
            "strings": strings,
            "note": "Full CSStore decode is not implemented; URL / bundle-id string scrape only",
        }))
    }
}
