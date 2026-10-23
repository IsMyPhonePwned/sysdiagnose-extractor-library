//! Parse `mount.txt` (system partition sealed / read-only integrity check).

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::matching_utf8_files;
use crate::parsers::parser_helpers::parse_mount_txt;
use crate::parsers::SysdiagnoseParser;

pub struct MountParser;

impl SysdiagnoseParser for MountParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, &["mount.txt"])?;
        if files.is_empty() {
            return Ok(json!({ "error": ["No mount.txt file present"] }));
        }
        let mut events = Vec::new();
        let mut summary = json!({});
        for (_, text) in files {
            let (ev, sum) = parse_mount_txt(&text, "mount");
            events.extend(ev);
            summary = sum;
        }
        Ok(json!({
            "parser": "mount",
            "format": "jsonl",
            "events": events,
            "summary": summary,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn detects_sealed_readonly_root() {
        let text = concat!(
            "/dev/disk0s1s1 on / (apfs, sealed, local, nosuid, read-only, journaled)\n",
            "devfs on /dev (devfs, local)\n",
        );
        let mut m = HashMap::new();
        m.insert(
            "mount.txt".to_string(),
            Arc::from(text.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let out = MountParser.parse(&arch).expect("parse");
        assert_eq!(out["summary"]["root_sealed"], true);
        assert_eq!(out["summary"]["root_read_only"], true);
        assert_eq!(
            out["summary"]["integrity_hint"],
            "system_partition_sealed_readonly"
        );
    }
}
