//! Port of SAF [`brctl.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/brctl.py).

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::brctl_parsed;
use crate::parsers::SysdiagnoseParser;

pub struct BrctlParser;

impl SysdiagnoseParser for BrctlParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let data = brctl_parsed(archive);
        Ok(json!({
            "parser": "brctl",
            "data": data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn structured_brctl_output() {
        let mut m = HashMap::new();
        m.insert(
            "brctl/brctl-container-list.txt".into(),
            Arc::from(
                b"id: X localizedName: Y documents: Mobile Documents clients: [a]"
                    .to_vec()
                    .into_boxed_slice(),
            ),
        );
        m.insert(
            "brctl/brctl-dump.txt".into(),
            Arc::from(
                b"header line\n-----------------------------------------------------\n"
                    .to_vec()
                    .into_boxed_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = BrctlParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "brctl");
        assert!(v["data"]["containers"].is_array());
    }
}
