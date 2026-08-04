//! Port of SAF [`avconference_callsettings.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/avconference_callsettings.py).

use chrono::{FixedOffset, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use super::common::saf_event_dict;

pub fn parse_avconference_gzip(
    path: &str,
    decompressed: &[u8],
    module: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
    let fname = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    static TSFN: OnceLock<Regex> = OnceLock::new();
    let re = TSFN.get_or_init(|| Regex::new(r"([0-9]{8}-[0-9]{6})-").expect("fname ts"));
    let cap = re
        .captures(fname)
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "no timestamp in filename".into()
        })?;
    let ts_raw = cap.get(1).map(|m| m.as_str()).unwrap_or("");
    let naive = NaiveDateTime::parse_from_str(ts_raw, "%Y%m%d-%H%M%S")
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    let dt = Utc
        .from_utc_datetime(&naive)
        .with_timezone(&FixedOffset::east_opt(0).unwrap());

    let text = std::str::from_utf8(decompressed)?;
    static LINE_TS: OnceLock<Regex> = OnceLock::new();
    let line_ts = LINE_TS.get_or_init(|| Regex::new(r"^[0-9]{6}\.[0-9]{6} ").expect("line ts"));

    let mut out = Vec::new();
    for line in text.lines() {
        let message = if line_ts.is_match(line) {
            line.get(13..).unwrap_or("").trim()
        } else {
            line.trim()
        };
        out.push(saf_event_dict(
            module,
            dt,
            module,
            message,
            serde_json::json!({}),
        ));
    }
    Ok(out)
}

pub fn decompress_gzip(b: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut dec = flate2::read::GzDecoder::new(std::io::Cursor::new(b));
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}
