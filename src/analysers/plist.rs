//! MDM-related plist highlights from capped `plists` output.

use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::parsers::ParserType;

use super::common::{get_or_parse, plist_top_keys, ParsedByParser};

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let plists = get_or_parse(archive, parsed, ParserType::plists);
    let mut events = Vec::new();
    let mut file_count = 0usize;
    if let Some(files) = plists.get("files").and_then(|f| f.as_object()) {
        file_count = files.len();
        for (path, val) in files {
            let pl = path.to_ascii_lowercase();
            if path.contains("MCState") && path.contains("MDM") {
                let mut m = Map::new();
                m.insert("source".to_string(), json!(path));
                if pl.contains("shared_mdm") || pl.ends_with("mdm.plist") {
                    m.insert("kind".to_string(), json!("mdm_profile_fields"));
                    m.insert(
                        "ManagingProfileIdentifier".to_string(),
                        val.get("ManagingProfileIdentifier")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                    m.insert(
                        "AccessRights".to_string(),
                        val.get("AccessRights").cloned().unwrap_or(Value::Null),
                    );
                    m.insert(
                        "LastPollingAttempt".to_string(),
                        val.get("LastPollingAttempt")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                } else {
                    m.insert("kind".to_string(), json!("mdm_plist_candidate"));
                }
                m.insert("keys".to_string(), json!(plist_top_keys(val)));
                events.push(Value::Object(m));
            }
        }
    }
    json!({
        "analyser": "plist",
        "plist_files_parsed": file_count,
        "events": events,
        "saf_comparison": "SAF PListAnalyzer reads parser-emitted JSONL for logs_MCState_Shared_MDM; we scan capped `plists` output and surface MDM fields when paths match Shared_MDM / MDM plists."
    })
}
