//! Port of upstream SAF [`structure_parser.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/ioreg_parsers/structure_parser.py).

use std::io::{BufRead, Cursor};

use regex::Regex;
use serde_json::{json, Map, Value};

use super::string_parser::parse_ioreg_value;

pub struct IORegStructParser {
    reader: Cursor<Vec<u8>>,
    curr_line: String,
    rollback_pos: u64,
}

impl IORegStructParser {
    pub fn parse_bytes(bytes: &[u8]) -> Value {
        if bytes.is_empty() {
            return Value::Object(Map::new());
        }
        let owned = bytes.to_vec();
        let mut p = Self {
            reader: Cursor::new(owned),
            curr_line: String::new(),
            rollback_pos: 0,
        };
        let mut tree = Map::new();
        p.recursive_loop(&mut tree);
        Value::Object(tree)
    }

    fn get_line(&mut self) {
        self.rollback_pos = self.reader.position();
        self.curr_line.clear();
        let mut buf = Vec::new();
        if self.reader.read_until(b'\n', &mut buf).is_ok() {
            self.curr_line = String::from_utf8_lossy(&buf)
                .trim_end_matches('\n')
                .to_string();
        }
    }

    fn recursive_call(&mut self, data_tree: &mut Map<String, Value>) {
        self.reader.set_position(self.rollback_pos);
        self.recursive_loop(data_tree);
    }

    fn check_start_node(&self) {
        if !self.curr_line.contains("+-o") {
            panic!("File has an invalid structure, '+-o' tag was not found in first line");
        }
    }

    fn parse_title(&self) -> (String, String) {
        if !self.curr_line.contains("+-o") {
            return (String::new(), String::new());
        }
        let whole_title = self.curr_line.split("+-o").nth(1).unwrap_or("").trim();
        let name = whole_title
            .split("<class")
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let data = if let Some(rest) = whole_title.split("<class").nth(1) {
            format!("<class {rest}").trim().to_string()
        } else {
            String::new()
        };
        (name, data)
    }

    fn dict_update(main_dict: &mut Map<String, Value>, patch: Map<String, Value>) {
        for (key, value) in patch {
            if let Some(existing) = main_dict.get(&key) {
                if let Some(arr) = existing.as_array() {
                    let mut v = arr.clone();
                    v.push(value);
                    main_dict.insert(key, Value::Array(v));
                } else {
                    main_dict.insert(key, json!([existing.clone(), value]));
                }
            } else {
                main_dict.insert(key, value);
            }
        }
    }

    fn dict_update_value(main_dict: &mut Map<String, Value>, patch: Value) {
        if let Value::Object(m) = patch {
            Self::dict_update(main_dict, m);
        } else if let Value::String(s) = patch {
            if !s.is_empty() {
                main_dict.insert("_title_raw".into(), Value::String(s));
            }
        }
    }

    fn handle_anomalies(dictio: &mut Map<String, Value>, data: &str, key: Option<&str>) {
        let Some(key) = key else {
            return;
        };
        let cond1 = !Regex::new(r"^\s*\|+").unwrap().is_match(data);
        let cond2 = !data.trim().is_empty();
        let cond3 = !matches!(data.trim(), "{" | "}");
        let cond4 = !data.contains('=');
        if cond1 && cond2 && cond3 && cond4 {
            if let Some(Value::String(s)) = dictio.get_mut(key) {
                s.push_str(data.trim());
            }
        }
    }

    fn node_data_to_json(data_array: &[String]) -> Map<String, Value> {
        let mut res = Map::new();
        let mut key: Option<String> = None;
        let re = Regex::new(r"^(\s|\|)*").unwrap();
        for data in data_array {
            Self::handle_anomalies(&mut res, data, key.as_deref());
            let clean_line = re.replace(data, "").to_string();
            if !clean_line.contains('=') {
                continue;
            }
            let (k, value) = clean_line.split_once('=').unwrap_or(("", ""));
            let mut k = k.replace('"', "");
            if k.starts_with('"') {
                k = k[1..].to_string();
            }
            if k.ends_with('"') {
                k = k[..k.len().saturating_sub(1)].to_string();
            }
            let k = k.trim().to_string();
            key = Some(k.clone());
            res.insert(k, Value::String(value.trim().to_string()));
        }
        res
    }

    fn parse_values(data_dict: &mut Map<String, Value>) {
        for (_, value) in data_dict.iter_mut() {
            if let Value::String(s) = value {
                let cleaned = Self::clean_plist_value_string(s);
                let parsed = parse_ioreg_value(&cleaned);
                if !parsed.is_null() {
                    *value = parsed;
                } else {
                    *value = Value::String(cleaned);
                }
            }
        }
    }

    fn clean_plist_value_string(s: &str) -> String {
        let s = s.trim();
        if s.starts_with('"') {
            // Keep quotes so string_parser treats `<` etc. as literal content.
            s.to_string()
        } else if s.ends_with('"') {
            s[..s.len().saturating_sub(1)].to_string()
        } else {
            s.to_string()
        }
    }

    fn fetch_node_data(&mut self, data_tree: &mut Map<String, Value>) -> bool {
        let mut node_data = Vec::new();
        loop {
            if self.curr_line.contains("+-o") {
                break;
            }
            if self.curr_line.is_empty() {
                return false;
            }
            node_data.push(self.curr_line.clone());
            self.get_line();
        }
        let mut data_dict = Self::node_data_to_json(&node_data);
        Self::parse_values(&mut data_dict);
        Self::dict_update(data_tree, data_dict);
        true
    }

    fn ensure_child_slot(data_tree: &mut Map<String, Value>, key: &str) {
        match data_tree.get(key) {
            None => {
                data_tree.insert(key.to_string(), json!({}));
            }
            Some(Value::Array(_)) => {
                if let Some(Value::Array(a)) = data_tree.get_mut(key) {
                    a.push(json!({}));
                }
            }
            Some(Value::Object(_)) => {
                let prev = data_tree.remove(key).unwrap();
                data_tree.insert(key.to_string(), json!([prev, {}]));
            }
            Some(_) => {
                let prev = data_tree.remove(key).unwrap();
                data_tree.insert(key.to_string(), json!([prev, {}]));
            }
        }
    }

    fn child_map_mut<'b>(
        data_tree: &'b mut Map<String, Value>,
        key: &str,
    ) -> Option<&'b mut Map<String, Value>> {
        match data_tree.get_mut(key) {
            Some(Value::Object(m)) => Some(m),
            Some(Value::Array(a)) => a.last_mut().and_then(|v| v.as_object_mut()),
            _ => None,
        }
    }

    fn iterate_children(&mut self, depth: usize, data_tree: &mut Map<String, Value>) {
        while !self.curr_line.is_empty()
            && (self.curr_line.chars().nth(depth) == Some('|')
                || self.curr_line[depth..].starts_with("+-o"))
        {
            if self.curr_line[depth..].starts_with("+-o") {
                let (name, _) = self.parse_title();
                Self::ensure_child_slot(data_tree, &name);
                if let Some(child) = Self::child_map_mut(data_tree, &name) {
                    self.recursive_call(child);
                }
            } else {
                self.get_line();
            }
        }
    }

    fn recursive_loop(&mut self, data_tree: &mut Map<String, Value>) {
        self.get_line();
        self.check_start_node();
        let (_name, title_data) = self.parse_title();
        let additional = parse_ioreg_value(&title_data);
        Self::dict_update_value(data_tree, additional);
        let depth = self.curr_line.find('o').unwrap_or(0);
        self.get_line();
        let is_leaf = self.curr_line.chars().nth(depth) != Some('|');
        if !self.fetch_node_data(data_tree) {
            return;
        }
        if is_leaf {
            self.reader.set_position(self.rollback_pos);
            return;
        }
        self.iterate_children(depth, data_tree);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const BASIC_FIXTURE: &str = include_str!("../../../testdata/fixtures/ioreg_basic.txt");

    #[test]
    fn basic_structure_matches_upstream_fixture() {
        let tree = IORegStructParser::parse_bytes(BASIC_FIXTURE.as_bytes());
        let obj = tree.as_object().expect("tree object");
        assert_eq!(obj.get("class"), Some(&json!("test1")));
        assert_eq!(obj.get("key1"), Some(&json!("val1")));
        assert!(obj.contains_key("Node 2"));
        let node2 = obj.get("Node 2").unwrap().as_object().unwrap();
        assert_eq!(node2.get("#address-cells"), Some(&json!("<02000000>")));
    }

    #[test]
    fn parse_empty_returns_empty_object() {
        let tree = IORegStructParser::parse_bytes(b"");
        assert_eq!(tree, json!({}));
    }

    #[test]
    fn fixture_file_on_disk_matches_include() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/fixtures/ioreg_basic.txt");
        let bytes = fs::read(path).expect("fixture");
        let tree = IORegStructParser::parse_bytes(&bytes);
        assert!(tree.get("Node 2").is_some());
    }

    #[test]
    fn overflow_anomaly_fixture() {
        const FIXTURE: &str = include_str!("../../../testdata/fixtures/ioreg_overflow.txt");
        let tree = IORegStructParser::parse_bytes(FIXTURE.as_bytes());
        let leaf2 = tree
            .pointer("/Node 2/Node 3/Leaf 2")
            .and_then(|v| v.as_object())
            .expect("Leaf 2");
        assert_eq!(
            leaf2.get("data l4").and_then(|v| v.as_str()),
            Some("value aaaabbbbccccdddd")
        );
    }

    #[test]
    fn non_ascii_byte_in_value() {
        let mut fixture = String::from(include_str!("../../../testdata/fixtures/ioreg_non_ascii.txt"));
        fixture = fixture.replace("value -->\\xbf<--", "value -->\u{bf}<--");
        let tree = IORegStructParser::parse_bytes(fixture.as_bytes());
        let leaf2 = tree
            .pointer("/Node 2/Node 3/Leaf 2")
            .and_then(|v| v.as_object())
            .expect("Leaf 2");
        assert_eq!(
            leaf2.get("data l4").and_then(|v| v.as_str()),
            Some("value -->\u{bf}<--")
        );
    }
}
