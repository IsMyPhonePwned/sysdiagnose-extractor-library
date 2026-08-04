//! SAF [`Event::to_dict`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/base.py) shape and sysdiagnose bundle timestamps.

use chrono::{DateTime, FixedOffset, LocalResult, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;

/// One SAF-style event object (`datetime`, `message`, `timestamp_desc`, `module`, `data`).
pub fn saf_event_dict(
    module: &str,
    dt: DateTime<FixedOffset>,
    timestamp_desc: &str,
    message: &str,
    data: Value,
) -> Value {
    json!({
        "datetime": dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "message": message,
        "timestamp_desc": timestamp_desc,
        "module": module,
        "data": data,
    })
}

pub fn wrap_jsonl(parser_id: &str, events: Vec<Value>) -> Value {
    json!({
        "parser": parser_id,
        "format": "jsonl",
        "events": events,
    })
}

/// Mirrors SAF `BaseInterface.sysdiagnose_creation_datetime` (log file, then bundle name).
pub fn sysdiagnose_creation(archive: &SysdiagnoseArchive) -> DateTime<FixedOffset> {
    if let Some((_, bytes)) = archive.find_suffix("sysdiagnose.log") {
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Some(dt) = parse_sysdiagnose_timestamp_from_log(text) {
                return dt;
            }
        }
    }
    if let Some(dt) = archive.acquisition() {
        return dt;
    }
    Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap())
}

fn parse_sysdiagnose_timestamp_from_log(content: &str) -> Option<DateTime<FixedOffset>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"IN_PROGRESS_sysdiagnose_(\d{4}\.\d{2}\.\d{2}_\d{2}-\d{2}-\d{2}[+-]\d{4})_|spindump_sysdiagnose_(\d{4}\.\d{2}\.\d{2}_\d{2}-\d{2}-\d{2}[+-]\d{4})_",
        )
        .expect("regex")
    });
    let cap = re.captures(content)?;
    let ts = cap.get(1).or_else(|| cap.get(2))?.as_str();
    DateTime::parse_from_str(ts, "%Y.%m.%d_%H-%M-%S%z").ok()
}

pub fn naive_with_offset(naive: NaiveDateTime, tz: FixedOffset) -> DateTime<FixedOffset> {
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(dt) => dt,
        LocalResult::Ambiguous(earliest, _) => earliest,
        LocalResult::None => tz.from_utc_datetime(&naive),
    }
}

/// UTC `NaiveDateTime` → `DateTime<FixedOffset>` at +00:00 (matches SAF `timezone.utc` stamps).
pub fn naive_utc(naive: NaiveDateTime) -> DateTime<FixedOffset> {
    Utc.from_utc_datetime(&naive)
        .with_timezone(&FixedOffset::east_opt(0).unwrap())
}
