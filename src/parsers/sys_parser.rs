//! Port of SAF `parsers/sys.py` (`logs/SystemVersion/SystemVersion.plist`).

use serde_json::{json, Value};
use std::error::Error;
use std::io::Cursor;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;

const PRIMARY: &str = "logs/SystemVersion/SystemVersion.plist";
const FALLBACK: &str = "logs/Splat/OS/SystemVersion.plist";

pub struct SystemVersionParser;

impl SysdiagnoseParser for SystemVersionParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let (source, bytes) = if let Some(b) = archive.get(PRIMARY) {
            (PRIMARY, b)
        } else if let Some(b) = archive.get(FALLBACK) {
            (FALLBACK, b)
        } else if let Some((p, b)) = archive.find_suffix("SystemVersion.plist") {
            (p, b)
        } else {
            return Ok(json!({
                "parser": "sys",
                "source": PRIMARY,
                "error": "No SystemVersion.plist file present",
                "plist": Value::Null
            }));
        };

        if bytes.is_empty() {
            return Ok(json!({
                "parser": "sys",
                "source": source,
                "error": "Empty plist file",
                "plist": Value::Null
            }));
        }

        let plist_val: plist::Value = plist::from_reader(Cursor::new(bytes))
            .map_err(|e| format!("Invalid plist at {source}: {e}"))?;
        let plist_json =
            serde_json::to_value(&plist_val).map_err(|e| format!("Plist to JSON: {e}"))?;

        let pn = plist_json
            .get("ProductName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pv = plist_json
            .get("ProductVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let bv = plist_json
            .get("BuildVersion")
            .or_else(|| plist_json.get("ProductBuildVersion"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let message = format!("SystemVersion {pn} {pv} {bv}").trim().to_string();

        Ok(json!({
            "parser": "sys",
            "source": source,
            "message": message,
            "plist": plist_json
        }))
    }
}
