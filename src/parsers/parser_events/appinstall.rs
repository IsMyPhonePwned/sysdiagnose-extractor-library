//! Port of SAF [`appinstallation.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/appinstallation.py).

use chrono::{FixedOffset, TimeZone, Utc};
use serde_json::{json, Value};

use super::common::saf_event_dict;

/// Converts a per-database `{ table: [rows] }` JSON blob into SAF-style events (rows with `timestamp` unix field).
pub fn appinstallation_events_from_tables(db_json: &Value, module: &str) -> Vec<Value> {
    let mut result = Vec::new();
    let Some(root) = db_json.as_object() else {
        return result;
    };
    for (table_name, rows_val) in root {
        if table_name.contains("sqlite_sequence") {
            continue;
        }
        let Some(rows) = rows_val.as_array() else {
            continue;
        };
        for row in rows {
            let Some(item) = row.as_object() else {
                continue;
            };
            if !item.contains_key("timestamp") {
                continue;
            }
            let ts = item
                .get("timestamp")
                .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)));
            let Some(ts) = ts else { continue };
            let Some(dt_utc) = Utc.timestamp_opt(ts, 0).single() else {
                continue;
            };
            let dt = dt_utc.with_timezone(&FixedOffset::east_opt(0).unwrap());
            let mut data = item.clone();
            data.insert("db_table".into(), json!(table_name));
            result.push(saf_event_dict(
                module,
                dt,
                table_name,
                "",
                Value::Object(data),
            ));
        }
    }
    result
}
