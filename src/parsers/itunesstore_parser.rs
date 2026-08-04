//! Port of SAF [`itunesstore.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/itunesstore.py).

use serde_json::{json, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::sqlite_first_db_tables;
use crate::parsers::SysdiagnoseParser;

pub struct ItunesstoreParser;

impl SysdiagnoseParser for ItunesstoreParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let inner = sqlite_first_db_tables(archive, &["logs/itunesstored/downloads.*.sqlitedb"])?;
        if inner.as_object().is_none_or(|o| o.is_empty()) {
            return Ok(json!({ "parser": "itunesstore", "data": {} }));
        }
        Ok(json!({
            "parser": "itunesstore",
            "source_path": inner.get("source_path").cloned().unwrap_or(json!(null)),
            "data": inner.get("data").cloned().unwrap_or(json!({})),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn sample_itunes_db_bytes() -> Vec<u8> {
        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE download (bundle_id TEXT, application_id TEXT);
             INSERT INTO download VALUES ('com.example.app', 'app');",
        )
        .unwrap();
        std::fs::read(path.path()).unwrap()
    }

    #[test]
    fn first_db_tables_shape() {
        let mut m = HashMap::new();
        m.insert(
            "logs/itunesstored/downloads.28.sqlitedb".into(),
            Arc::from(sample_itunes_db_bytes().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = ItunesstoreParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "itunesstore");
        assert_eq!(
            v["source_path"],
            "logs/itunesstored/downloads.28.sqlitedb"
        );
        let rows = v["data"]["download"].as_array().unwrap();
        assert_eq!(rows[0]["bundle_id"], "com.example.app");
    }
}
