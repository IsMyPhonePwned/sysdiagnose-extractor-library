//! Port of SAF [`battery_bdc.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/battery_bdc.py).

use chrono::{FixedOffset, NaiveDateTime, TimeZone, Utc};
use serde_json::{json, Map, Value};
use std::error::Error;

use super::common::saf_event_dict;

pub fn parse_battery_bdc_csv(
    text: &str,
    module: &str,
    entry_type: &str,
) -> Result<Vec<Value>, Box<dyn Error + Send + Sync>> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = rdr.headers()?.clone();
    let mut out = Vec::new();
    for result in rdr.records() {
        let record = result?;
        let mut row = Map::new();
        for (i, h) in headers.iter().enumerate() {
            if let Some(f) = record.get(i) {
                row.insert(h.to_string(), json!(f));
            }
        }
        row.insert("type".into(), json!(entry_type));

        let (ts, ts_desc) = if let Some(Value::String(ts_s)) = row.get("TimeStamp") {
            let naive = NaiveDateTime::parse_from_str(ts_s, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;
            let dt = Utc
                .from_utc_datetime(&naive)
                .with_timezone(&FixedOffset::east_opt(0).unwrap());
            row.remove("TimeStamp");
            (dt, entry_type.to_string())
        } else if let Some(Value::String(ts_s)) = row.get("set_system_time") {
            let dt = chrono::DateTime::parse_from_str(ts_s, "%Y-%m-%d %H:%M:%S %z")
                .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;
            row.remove("set_system_time");
            (dt, entry_type.to_string())
        } else {
            continue;
        };

        let data = Value::Object(row);
        out.push(saf_event_dict(
            module,
            ts,
            &ts_desc,
            "power state report",
            data,
        ));
    }
    Ok(out)
}
