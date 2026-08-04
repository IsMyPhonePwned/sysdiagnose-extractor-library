//! Port of SAF `parsers/transparency_json.py` (structured extract).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;

pub struct TransparencyJsonParser;

impl SysdiagnoseParser for TransparencyJsonParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        return crate::parsers::parser_helpers::json_whole_first(archive, &["transparency.log"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn empty_transparency_log_is_soft_error() {
        let mut m = HashMap::new();
        m.insert(
            "transparency.log".into(),
            Arc::from(b"".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TransparencyJsonParser.parse(&arch).expect("ok");
        assert_eq!(v.get("error"), Some(&json!("empty_file")));
    }

    #[test]
    fn whitespace_only_transparency_log_is_soft_error() {
        let mut m = HashMap::new();
        m.insert(
            "transparency.log".into(),
            Arc::from(b"  \n\t".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TransparencyJsonParser.parse(&arch).expect("ok");
        assert_eq!(v.get("error"), Some(&json!("empty_file")));
    }

    #[test]
    fn valid_transparency_json_parses() {
        let mut m = HashMap::new();
        m.insert(
            "transparency.log".into(),
            Arc::from(br#"{"stateMachine":{"devices":{}}}"#.to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TransparencyJsonParser.parse(&arch).expect("ok");
        assert!(v.get("stateMachine").is_some());
        assert!(v.get("error").is_none());
    }
}
