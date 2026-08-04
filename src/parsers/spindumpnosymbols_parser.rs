//! Port of SAF [`spindumpnosymbols.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/src/sysdiagnose/parsers/spindumpnosymbols.py)
//! — jsonl **`events`** via [`wrap_jsonl`](crate::parsers::parser_events::wrap_jsonl), same section model as upstream.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_events::{
    matching_utf8_files, parse_spindump_nosymbols_text, wrap_jsonl,
};
use crate::parsers::SysdiagnoseParser;

/// Glob for `spindump-nosymbols.txt` at bundle root or under a subdirectory.
const SPINDUMP_PATTERNS: &[&str] = &["**/spindump-nosymbols.txt"];

pub struct SpindumpnosymbolsParser;

impl SysdiagnoseParser for SpindumpnosymbolsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let files = matching_utf8_files(archive, SPINDUMP_PATTERNS)?;
        if files.is_empty() {
            return Ok(wrap_jsonl("spindumpnosymbols", vec![]));
        }
        let mut events = Vec::new();
        for (_path, text) in files {
            events.extend(parse_spindump_nosymbols_text(&text));
        }
        Ok(wrap_jsonl("spindumpnosymbols", events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    const MINI: &str = r#"Date/Time:       2020-01-02 10:00:00 +0000
Data Source:     Stackshots

------------------------------------------------------------
Process:         launchd [1]
Path:            /sbin/launchd
UID:             0
Time since fork: 10s

Thread 0x1234 priority 31
  (libsystem_kernel.dylib+0x123) [0xabc]

Binary Images:
0x1000 - 0x2000  dyld  (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)  /usr/lib/dyld
"#;

    #[test]
    fn parser_wraps_fixture_events() {
        let mut m = HashMap::new();
        m.insert(
            "logs/spindump-nosymbols.txt".to_string(),
            Arc::from(MINI.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = SpindumpnosymbolsParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "spindumpnosymbols");
        assert_eq!(v["format"], "jsonl");
        let evs = v["events"].as_array().expect("events");
        assert!(evs.len() >= 2);
    }
}
