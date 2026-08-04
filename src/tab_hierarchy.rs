//! Tab-indented hierarchical text blocks, ported from SAF `utils/tabbasedhierarchy.py`.

use regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

fn re_arrow() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(.+?)=>*(.*)$").expect("regex"))
}

fn re_colon() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([^:]+):(.*)$").expect("regex"))
}

#[inline]
fn tab_depth(line: &str) -> usize {
    line.chars().take_while(|&c| c == '\t').count()
}

fn subsection_key(line: &str) -> String {
    if line.contains("=>") {
        line.split("=>").next().unwrap_or("").trim().to_string()
    } else {
        line.replace(':', "").replace('{', "").trim().to_string()
    }
}

/// Strip matching outer quotes recursively (SAF `clean_value`).
pub fn clean_value(value: &str) -> String {
    let mut value = value.trim().to_string();
    loop {
        let v = value.trim();
        if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            value = v[1..v.len() - 1].to_string();
            continue;
        }
        if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
            value = v[1..v.len() - 1].to_string();
            continue;
        }
        break;
    }
    value
}

/// Full-file tab hierarchy parse (SAF `parse_tab_based_hierarchal_file` without path I/O).
pub fn parse_tab_hierarchy_text(text: &str) -> Value {
    let lines: Vec<String> = text.lines().map(String::from).collect();
    parse_block(&lines)
}

/// Parse a block of lines into a JSON object or array (SAF `parse_block`).
pub fn parse_block(lines: &[String]) -> Value {
    let mut result: Option<Value> = None;
    let mut n = 0usize;

    while n < lines.len() {
        let line = &lines[n];
        let stripped = line.trim();
        if stripped == "}" || stripped.is_empty() || stripped == "]" {
            n += 1;
            continue;
        }

        let current_depth = tab_depth(line);
        let next_depth = lines
            .get(n + 1)
            .map(|l| tab_depth(l))
            .unwrap_or(current_depth);

        if next_depth > current_depth {
            let key = subsection_key(line);
            let sub_start = n + 1;
            let mut k = n;
            let mut nd = next_depth;
            while nd > current_depth {
                k += 1;
                if k >= lines.len() {
                    break;
                }
                nd = lines
                    .get(k + 1)
                    .map(|l| tab_depth(l))
                    .unwrap_or(current_depth);
            }
            if k >= sub_start && k < lines.len() {
                let sub = parse_block(&lines[sub_start..=k]);
                match &mut result {
                    None => {
                        let mut m = Map::new();
                        m.insert(key, sub);
                        result = Some(Value::Object(m));
                    }
                    Some(Value::Object(m)) => {
                        m.insert(key, sub);
                    }
                    Some(_) => {
                        let mut m = Map::new();
                        m.insert(key, sub);
                        result = Some(Value::Object(m));
                    }
                }
            }
            n = k + 1;
            continue;
        }

        let trimmed = stripped;
        let mut key_opt: Option<String> = None;
        let mut val_opt: Option<String> = None;
        if let Some(c) = re_arrow().captures(trimmed) {
            key_opt = Some(c.get(1).unwrap().as_str().trim().to_string());
            val_opt = Some(clean_value(c.get(2).unwrap().as_str()));
        } else if let Some(c) = re_colon().captures(trimmed) {
            key_opt = Some(c.get(1).unwrap().as_str().trim().to_string());
            val_opt = Some(clean_value(c.get(2).unwrap().as_str()));
        }

        if let Some(k) = key_opt {
            if result.is_none() {
                result = Some(Value::Object(Map::new()));
            }
            if let Some(Value::Object(m)) = &mut result {
                m.insert(k, Value::String(val_opt.unwrap_or_default()));
            }
        } else if let Some(Value::Object(m)) = &mut result {
            m.insert(trimmed.to_string(), Value::String(String::new()));
        } else {
            if result.is_none() {
                result = Some(Value::Array(vec![]));
            }
            if let Some(Value::Array(a)) = &mut result {
                a.push(Value::String(trimmed.to_string()));
            }
        }
        n += 1;
    }

    result.unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nested_subsection() {
        let lines: Vec<String> = vec!["parent:".to_string(), "\tchild: x".to_string()];
        let v = parse_block(&lines);
        let m = v.as_object().unwrap();
        assert!(m.get("parent").is_some());
    }

    #[test]
    fn golden_remotectl_fixture() {
        const FIXTURE: &str =
            include_str!("../testdata/fixtures/remotectl_dumpstate_golden.txt");
        let v = parse_tab_hierarchy_text(FIXTURE);
        let device = v.get("Device").and_then(|d| d.as_object()).expect("Device");
        assert_eq!(
            device.get("OSVersion").and_then(|x| x.as_str()),
            Some("17.2.1")
        );
        assert_eq!(
            device.get("SerialNumber").and_then(|x| x.as_str()),
            Some("GOLDEN123")
        );
        let services = v
            .get("Services")
            .and_then(|s| s.as_array())
            .expect("Services");
        assert!(services.iter().any(|x| x.as_str() == Some("com.apple.springboard")));
    }
}
