//! Port of SAF [`plists.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/plists.py).

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::plists_config::PlistsCaps;
use crate::parsers::SysdiagnoseParser;

pub struct PlistsParser;

impl SysdiagnoseParser for PlistsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let caps = PlistsCaps::from_env();
        let bundle = crate::parsers::parser_helpers::plists_recursive_with_caps(archive, caps);
        let files = bundle.get("files").cloned().unwrap_or(json!({}));
        let meta = bundle.get("meta").cloned().unwrap_or(json!({}));
        Ok(json!({
            "parser": "plists",
            "files": files,
            "meta": meta,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn parse_failure_yields_empty_object() {
        let mut m = HashMap::new();
        m.insert(
            "broken.plist".into(),
            Arc::from(b"not a plist".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let caps = PlistsCaps {
            max_files: 0,
            max_each_bytes: 0,
        };
        let v = crate::parsers::parser_helpers::plists_recursive_with_caps(&arch, caps);
        assert_eq!(v["files"]["broken.plist"], json!({}));
        assert!(v["meta"]["parse_failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "broken.plist"));
    }

    #[test]
    fn respects_max_files_cap() {
        let mut m = HashMap::new();
        for i in 0..3 {
            m.insert(
                format!("a{i}.plist"),
                Arc::from(
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>k</key><string>v</string></dict></plist>"#
                        .to_vec()
                        .into_boxed_slice(),
                ),
            );
        }
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let caps = PlistsCaps {
            max_files: 2,
            max_each_bytes: 0,
        };
        let v = crate::parsers::parser_helpers::plists_recursive_with_caps(&arch, caps);
        assert_eq!(v["meta"]["truncated_file_count"], 1);
        assert_eq!(v["files"].as_object().unwrap().len(), 2);
    }
}
