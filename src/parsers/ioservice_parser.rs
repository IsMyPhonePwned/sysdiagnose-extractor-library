//! Port of SAF `parsers/ioservice.py` (IOReg structured tree).
//!
//! `IOService.txt` is often very large. By default this parser returns a **compact**
//! preview (`format: "compact"`) with stats, device-related properties, and a
//! depth-limited `tree`. Pass [`ParseOptions::ioservice_full_tree`] for the full tree.

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::ioreg::{
    compact_tree, extract_interesting_properties, ioservice_compact_opts, tree_stats,
    IORegStructParser,
};
use crate::parsers::parser_helpers::{ioreg_parse_result, MAX_UTF8_FILE};
use crate::parsers::{ParseOptions, SysdiagnoseParser};

const PATH: &str = "ioreg/IOService.txt";
const PARSER_ID: &str = "ioservice";

pub struct IoserviceParser;

impl IoserviceParser {
    pub fn parse_with_options(
        &self,
        archive: &SysdiagnoseArchive,
        options: &ParseOptions,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        if options.ioservice_full_tree {
            return Ok(ioreg_parse_result(archive, PATH, PARSER_ID));
        }
        Ok(ioservice_compact_result(archive))
    }
}

impl SysdiagnoseParser for IoserviceParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        self.parse_with_options(archive, &ParseOptions::default())
    }
}

fn ioservice_compact_result(archive: &SysdiagnoseArchive) -> Value {
    let Some(bytes) = archive.get(PATH) else {
        return json!({});
    };
    if bytes.len() > MAX_UTF8_FILE {
        return json!({
            "parser": PARSER_ID,
            "error": "oversized",
            "path": PATH,
            "size": bytes.len(),
        });
    }

    let tree = IORegStructParser::parse_bytes(bytes);
    let (node_count, property_count) = tree_stats(&tree);
    let device_properties = extract_interesting_properties(&tree);
    let opts = ioservice_compact_opts();
    let (compact, tree_truncated) = compact_tree(&tree, &opts);

    let top_level_keys: Vec<_> = tree
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    json!({
        "parser": PARSER_ID,
        "format": "compact",
        "summary": {
            "source_path": PATH,
            "source_bytes": bytes.len(),
            "node_count": node_count,
            "property_count": property_count,
            "top_level_keys": top_level_keys,
        },
        "device_properties": Value::Object(device_properties),
        "tree": compact,
        "meta": {
            "tree_truncated": tree_truncated,
            "max_depth": opts.max_depth,
            "max_children_per_node": opts.max_children,
            "full_tree_hint": "Pass ParseOptions { ioservice_full_tree: true } or sdx-cli --ioservice-full-tree",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn fixture_archive() -> SysdiagnoseArchive {
        let fixture = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/fixtures/ioreg_basic.txt"
        ));
        let mut m = HashMap::new();
        m.insert(
            PATH.to_string(),
            Arc::from(fixture.to_vec().into_boxed_slice()),
        );
        SysdiagnoseArchive::from_files_for_test(m)
    }

    #[test]
    fn compact_ioservice_from_fixture() {
        let arch = fixture_archive();
        let v = IoserviceParser.parse(&arch).unwrap();
        assert_eq!(v["format"], "compact");
        assert!(v["summary"]["node_count"].as_u64().unwrap() >= 1);
        assert!(v.get("tree").is_some());
    }

    #[test]
    fn full_tree_via_parse_options() {
        let arch = fixture_archive();
        let opts = ParseOptions {
            ioservice_full_tree: true,
            ..Default::default()
        };
        let v = IoserviceParser
            .parse_with_options(&arch, &opts)
            .unwrap();
        assert_eq!(v["parser"], PARSER_ID);
        assert!(v.get("format").is_none());
        assert!(v.get("tree").is_some());
    }
}
