//! Port of upstream SAF [`brctl.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/brctl.py).

use std::collections::HashMap;

use regex::Regex;
use serde_json::{json, Map, Value};

pub fn parse_brctl_folder(container_list: &str, container_dump: &str) -> Value {
    let mut out = Map::new();
    out.extend(parse_list_file(container_list));
    if let Value::Object(dump) = parse_dump_file(container_dump) {
        out.extend(dump);
    }
    Value::Object(out)
}

fn parse_list_file(text: &str) -> Map<String, Value> {
    let keys = [
        "id",
        "localizedName",
        "documents",
        "Public",
        "Private",
        "clients",
    ];
    let pattern = format!(r"({}):\s*([^ \[]+|\[[^\]]*\])", keys.join("|"));
    let re = Regex::new(&pattern).expect("brctl list regex");
    let mut containers = Vec::new();
    for line in text.lines() {
        let line = line.trim().replace("Mobile Documents", "Mobile_Documents");
        let mut result = Map::new();
        for cap in re.captures_iter(&line) {
            let k = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut v = cap
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if v.starts_with('[') && v.ends_with(']') {
                v = v[1..v.len() - 1].to_string();
            }
            result.insert(k.to_string(), Value::String(v));
        }
        if !result.is_empty() {
            if let Some(Value::String(docs)) = result.get_mut("documents") {
                *docs = docs.replace("Mobile_Documents", "Mobile Documents");
            }
            containers.push(Value::Object(result));
        }
    }
    let mut m = Map::new();
    m.insert("containers".into(), Value::Array(containers));
    m
}

fn parse_dump_file(text: &str) -> Value {
    let mut dump: HashMap<String, String> = HashMap::new();
    let mut section = "header".to_string();
    let mut previous_line = String::new();
    let mut current_section = String::new();
    for line in text.lines() {
        if line.trim() == "-----------------------------------------------------" {
            dump.insert(section.clone(), std::mem::take(&mut current_section));
            section = previous_line.trim().to_string();
            current_section.clear();
        } else {
            previous_line = line.to_string();
            current_section.push_str(line);
            current_section.push('\n');
        }
    }
    if !current_section.is_empty() {
        dump.insert(section, current_section);
    }

    let header = parse_header(dump.get("header").map(|s| s.as_str()).unwrap_or(""));
    let mut boot_history = Map::new();
    for (key, value) in &dump {
        if key.starts_with("boot_history") {
            boot_history.insert(key.clone(), Value::Array(parse_boot_history(value)));
        }
    }
    let server_state =
        parse_server_state(dump.get("server_state").map(|s| s.as_str()).unwrap_or(""));
    let client_state =
        parse_client_state(dump.get("client_state").map(|s| s.as_str()).unwrap_or(""));
    let system = parse_system_scheduler(dump.get("system").map(|s| s.as_str()).unwrap_or(""));
    let scheduler = parse_system_scheduler(dump.get("scheduler").map(|s| s.as_str()).unwrap_or(""));

    let mut applibrary = Value::Array(vec![]);
    let mut server_items = Value::Array(vec![]);
    let mut ckey = String::new();
    for (key, value) in &dump {
        if value.contains("+ app library:") {
            ckey = key.clone();
            applibrary = Value::Array(parse_app_library(value));
            server_items = Value::Array(parse_server_items(value));
        }
    }
    let _ = ckey;

    let (app_library_id, app_ids) = dump
        .get("apps monitor")
        .map(|s| parse_apps_monitor(s))
        .unwrap_or((json!({}), json!({})));

    json!({
        "header": header,
        "boot_history": Value::Object(boot_history),
        "server_state": server_state,
        "client_state": client_state,
        "system": system,
        "scheduler": scheduler,
        "applibrary": applibrary,
        "server_items": server_items,
        "app_library_id": app_library_id,
        "app_ids": app_ids,
    })
}

fn parse_header(header: &str) -> Value {
    let pattern = Regex::new(r"(\w+):\s+(.+)(?:\n|$)").expect("header kv");
    let mut output = Map::new();
    for cap in pattern.captures_iter(header) {
        let k = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let v = cap
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if v.contains(", ") {
            let parts: Vec<_> = v
                .split(", ")
                .map(|s| Value::String(s.to_string()))
                .collect();
            output.insert(k.to_string(), Value::Array(parts));
        } else if v.starts_with('<') && v.ends_with('>') {
            output.insert(k.to_string(), Value::String(v[1..v.len() - 1].to_string()));
        } else {
            output.insert(k.to_string(), Value::String(v));
        }
    }
    let stamp = Regex::new(
        r"dump taken at (\d{2}/\d{2}/\d{4}, \d{2}:\d{2}:\d{2}) \[account=(\d+)\] \[inCarry=(\w+)\] \[home=(.+)\]",
    )
    .expect("header stamp");
    if let Some(cap) = stamp.captures(header) {
        output.insert(
            "timestamp".into(),
            Value::String(cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string()),
        );
        output.insert(
            "account".into(),
            Value::String(cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string()),
        );
        output.insert(
            "inCarry".into(),
            Value::String(cap.get(3).map(|m| m.as_str()).unwrap_or("").to_string()),
        );
        output.insert(
            "home".into(),
            Value::String(cap.get(4).map(|m| m.as_str()).unwrap_or("").to_string()),
        );
    }
    Value::Object(output)
}

fn parse_boot_history(section: &str) -> Vec<Value> {
    let re = Regex::new(r"\[(.+?)\] OS:(.+?) CloudDocs:(.+?) BirdSchema:(.+?) DBSchema:(.+)")
        .expect("boot history");
    section
        .lines()
        .filter_map(|line| {
            re.captures(line).map(|cap| {
                json!({
                    "date": cap.get(1).map(|m| m.as_str()).unwrap_or(""),
                    "OS": cap.get(2).map(|m| m.as_str()).unwrap_or(""),
                    "CloudDocs": cap.get(3).map(|m| m.as_str()).unwrap_or(""),
                    "BirdSchema": cap.get(4).map(|m| m.as_str()).unwrap_or(""),
                    "DBSchema": cap.get(5).map(|m| m.as_str()).unwrap_or(""),
                })
            })
        })
        .collect()
}

fn parse_server_state(section: &str) -> Value {
    let re = Regex::new(r"(last-sync|nextRank|minUsedTime):(\S+)").expect("server state");
    let mut output = Map::new();
    for cap in re.captures_iter(section) {
        let field = cap
            .get(1)
            .map(|m| m.as_str().replace('-', "_"))
            .unwrap_or_default();
        let value = cap.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        if field == "shared_db" {
            output.insert(field, json!({}));
        } else {
            output.insert(field, Value::String(value.to_string()));
        }
    }
    Value::Object(output)
}

fn parse_client_state(data: &str) -> Value {
    let re = Regex::new(r"\s*(\w+)\s*=\s*(.*);").expect("client state");
    let mut parsed = Map::new();
    for line in data.lines() {
        if let Some(cap) = re.captures(line) {
            let key = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let value = cap
                .get(2)
                .map(|m| m.as_str().trim_matches('"'))
                .unwrap_or("")
                .to_string();
            let json_val = value
                .parse::<i64>()
                .map(|n| json!(n))
                .or_else(|_| value.parse::<f64>().map(|n| json!(n)))
                .unwrap_or_else(|_| Value::String(value));
            parsed.insert(key.to_string(), json_val);
        }
    }
    Value::Object(parsed)
}

fn parse_system_scheduler(input: &str) -> Value {
    let ansi = Regex::new(r"\x1b\[[0-9;]*m").expect("ansi");
    let mut data = Map::new();
    for line in input.lines() {
        let line = ansi.replace_all(line, "");
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('+') {
            if let Some((key, value)) = rest.split_once(':') {
                data.insert(
                    key.trim().to_string(),
                    Value::String(value.trim().to_string()),
                );
            }
        }
    }
    Value::Object(data)
}

fn parse_app_library(data: &str) -> Vec<Value> {
    let pattern = Regex::new(r"<(.*?)\[(\d+)\].*?ino:(\d+).*?apps:\{(.*?)\}.*?bundles:\{(.*?)\}")
        .expect("app library");
    pattern
        .captures_iter(data)
        .map(|cap| {
            let apps: Vec<_> = cap
                .get(4)
                .map(|m| m.as_str().split("; ").map(String::from).collect())
                .unwrap_or_default();
            let bundles: Vec<_> = cap
                .get(5)
                .map(|m| m.as_str().split(", ").map(String::from).collect())
                .unwrap_or_default();
            json!({
                "library": cap.get(1).map(|m| m.as_str()).unwrap_or(""),
                "ino": cap.get(3).map(|m| m.as_str()).unwrap_or(""),
                "apps": apps,
                "bundles": bundles,
            })
        })
        .collect()
}

fn parse_server_items(data: &str) -> Vec<Value> {
    let pattern = Regex::new(r"-+([^\[]+)\[(\d+)\]-+").expect("server items");
    data.lines()
        .filter(|l| l.contains("----------------------"))
        .filter_map(|line| {
            pattern.captures(line).map(|cap| {
                json!({
                    "library_name": cap.get(1).map(|m| m.as_str()).unwrap_or(""),
                    "library_id": cap.get(2).map(|m| m.as_str()).unwrap_or(""),
                })
            })
        })
        .collect()
}

fn parse_apps_monitor2json(data: &str) -> String {
    let mut json_str = data.replace('=', ":");
    json_str = Regex::new(r"\\n\s*")
        .unwrap()
        .replace_all(&json_str, "")
        .to_string();
    json_str = json_str
        .replace('\\', "")
        .replace("\"{(", "[")
        .replace(")}\";", "],")
        .replace('"', "");
    json_str = Regex::new(r"([\w\.\-]+)")
        .unwrap()
        .replace_all(&json_str, "\"$1\"")
        .to_string();
    if let Some(idx) = json_str.rfind(',') {
        json_str = format!("{}{}", &json_str[..idx], &json_str[idx + 1..]);
    }
    if let Some(idx) = json_str.find('}') {
        json_str = json_str[..=idx].to_string();
    }
    json_str
}

fn parse_apps_monitor(data: &str) -> (Value, Value) {
    let parts: Vec<_> = data.split("=======================").collect();
    if parts.len() < 3 {
        return (json!({}), json!({}));
    }
    let j1 = parse_apps_monitor2json(parts[1].trim());
    let j2 = parse_apps_monitor2json(parts[2].trim());
    let v1 = serde_json::from_str(&j1).unwrap_or_else(|_| json!({}));
    let v2 = serde_json::from_str(&j2).unwrap_or_else(|_| json!({}));
    (v1, v2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_container_list_line() {
        let list = "id: ABC localizedName: Test documents: Mobile Documents/Public clients: [a]";
        let m = parse_list_file(list);
        let arr = m.get("containers").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "ABC");
    }

    #[test]
    fn parses_boot_history_line() {
        let rows = parse_boot_history("[2020-01-01] OS:17 CloudDocs:1 BirdSchema:2 DBSchema:3\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["OS"], "17");
    }
}
