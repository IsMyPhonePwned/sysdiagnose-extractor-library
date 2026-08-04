//! Port of upstream SAF [`string_parser.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/string_parser.py).

use serde_json::{json, Map, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
enum StructType {
    None,
    StringSingle,
    StringDouble,
    XmlDict,
    CurlyDict,
    List,
    HookList,
    #[allow(dead_code)] // upstream string_parser.py parity
    MutatedString,
}

trait StructBox: std::any::Any {
    fn struct_type(&self) -> StructType;
    fn handle_char(&mut self, c: char);
    fn end_chunk(&mut self);
    fn post_treatment(&mut self);
    fn accepted_types(&self) -> &'static [StructType];
    fn add_struct(&mut self, child: Box<dyn StructBox>);
    fn into_value(self: Box<Self>) -> Value;
}

struct StackBase {
    data: Value,
}

impl StackBase {
    fn new() -> Self {
        Self {
            data: Value::String(String::new()),
        }
    }
}

impl StructBox for StackBase {
    fn struct_type(&self) -> StructType {
        StructType::None
    }

    fn handle_char(&mut self, c: char) {
        if let Value::String(s) = &mut self.data {
            s.push(c);
        }
    }

    fn end_chunk(&mut self) {}

    fn post_treatment(&mut self) {}

    fn accepted_types(&self) -> &'static [StructType] {
        all_types()
    }

    fn add_struct(&mut self, child: Box<dyn StructBox>) {
        self.data = child.into_value();
    }

    fn into_value(self: Box<Self>) -> Value {
        self.data
    }
}

macro_rules! string_struct {
    ($name:ident, $ty:expr, $start:expr, $end:expr, $keep_quotes:expr) => {
        struct $name {
            data: String,
        }

        impl $name {
            fn new() -> Self {
                Self {
                    data: String::new(),
                }
            }
        }

        impl StructBox for $name {
            fn struct_type(&self) -> StructType {
                $ty
            }

            fn handle_char(&mut self, c: char) {
                self.data.push(c);
            }

            fn end_chunk(&mut self) {}

            fn post_treatment(&mut self) {
                if $keep_quotes {
                    self.data = format!(
                        "{start}{data}{end}",
                        data = self.data,
                        start = $start,
                        end = $end
                    );
                }
            }

            fn accepted_types(&self) -> &'static [StructType] {
                &[]
            }

            fn add_struct(&mut self, _: Box<dyn StructBox>) {}

            fn into_value(self: Box<Self>) -> Value {
                Value::String(self.data)
            }
        }
    };
}

string_struct!(StringSingle, StructType::StringSingle, '\'', '\'', false);
string_struct!(StringDouble, StructType::StringDouble, '"', '"', false);

struct XmlDict {
    data: Map<String, Value>,
    currently_key: bool,
    temp_key: String,
    temp_val: Value,
    flag_key_is_string: bool,
    separator: char,
    start_char: char,
    end_char: char,
    struct_type: StructType,
}

impl XmlDict {
    fn new(separator: char, start: char, end: char, ty: StructType) -> Self {
        Self {
            data: Map::new(),
            currently_key: true,
            temp_key: String::new(),
            temp_val: Value::String(String::new()),
            flag_key_is_string: false,
            separator,
            start_char: start,
            end_char: end,
            struct_type: ty,
        }
    }

    fn values_reset(&mut self) {
        self.currently_key = true;
        self.temp_key.clear();
        self.temp_val = Value::String(String::new());
        self.flag_key_is_string = false;
    }

    fn flush_pair(&mut self) {
        if self.temp_key.trim().is_empty() {
            self.values_reset();
            return;
        }
        let mut key = self.temp_key.trim().to_string();
        let mut val = self.temp_val.clone();
        if let Value::String(s) = &mut val {
            *s = s.trim().to_string();
        }
        if val.is_null() || val.as_str().is_some_and(|s| s.is_empty()) {
            if self.currently_key && !self.flag_key_is_string {
                if let Some(stripped) = key.strip_prefix('!') {
                    key = stripped.to_string();
                    val = Value::Bool(false);
                } else {
                    val = Value::Bool(true);
                }
            }
        }
        if let Value::String(s) = &val {
            if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
                if let Ok(n) = s.parse::<i64>() {
                    val = json!(n);
                }
            }
        }
        self.data.insert(key, val);
        self.values_reset();
    }
}

impl StructBox for XmlDict {
    fn struct_type(&self) -> StructType {
        self.struct_type
    }

    fn handle_char(&mut self, c: char) {
        if c == self.separator && self.currently_key && !self.temp_key.is_empty() {
            self.currently_key = false;
            return;
        }
        if c == ',' {
            self.end_chunk();
            return;
        }
        if self.currently_key {
            self.temp_key.push(c);
        } else if let Value::String(s) = &mut self.temp_val {
            s.push(c);
        }
    }

    fn end_chunk(&mut self) {
        self.flush_pair();
    }

    fn post_treatment(&mut self) {
        self.end_chunk();
        let values: Vec<_> = self.data.values().cloned().collect();
        if values == [Value::String(String::new())]
            || values == [Value::Bool(true)]
            || values == [Value::Bool(false)]
        {
            let inner = self.data.keys().next().cloned().unwrap_or_default();
            self.data.clear();
            self.data.insert(
                "_mutated".into(),
                Value::String(format!(
                    "{start}{inner}{end}",
                    start = self.start_char,
                    end = self.end_char
                )),
            );
        } else if !self.data.is_empty()
            && self
                .data
                .values()
                .all(|v| v.as_str().is_some_and(|s| s.is_empty()))
        {
            let keys: Vec<_> = self.data.keys().cloned().collect();
            self.data.clear();
            self.data.insert("_list".into(), json!(keys));
        }
    }

    fn accepted_types(&self) -> &'static [StructType] {
        if self.currently_key {
            &[
                StructType::StringSingle,
                StructType::StringDouble,
                StructType::XmlDict,
                StructType::CurlyDict,
                StructType::List,
                StructType::HookList,
            ]
        } else {
            &[
                StructType::None,
                StructType::StringSingle,
                StructType::StringDouble,
                StructType::XmlDict,
                StructType::CurlyDict,
                StructType::List,
                StructType::HookList,
            ]
        }
    }

    fn add_struct(&mut self, child: Box<dyn StructBox>) {
        let val = child.into_value();
        if self.currently_key {
            if let Value::String(s) = val {
                self.temp_key.push_str(&s);
                self.flag_key_is_string = true;
            } else {
                self.temp_key.push_str(&val.to_string());
            }
        } else if let Value::String(s) = val {
            if let Value::String(dst) = &mut self.temp_val {
                dst.push_str(&s);
            } else {
                self.temp_val = Value::String(s);
            }
        } else {
            self.temp_val = val;
        }
    }

    fn into_value(self: Box<Self>) -> Value {
        if self.data.contains_key("_mutated") {
            return self.data["_mutated"].clone();
        }
        if let Some(list) = self.data.get("_list") {
            return list.clone();
        }
        Value::Object(self.data)
    }
}

struct ListLike {
    data: Vec<Value>,
    temp: Value,
    start_char: char,
    end_char: char,
    struct_type: StructType,
}

impl ListLike {
    fn new(start: char, end: char, ty: StructType) -> Self {
        Self {
            data: Vec::new(),
            temp: Value::String(String::new()),
            start_char: start,
            end_char: end,
            struct_type: ty,
        }
    }

    fn flush_temp(&mut self) {
        if let Value::String(s) = &self.temp {
            if !s.trim().is_empty() {
                self.data.push(Value::String(s.trim().to_string()));
            }
        } else {
            self.data.push(self.temp.clone());
        }
        self.temp = Value::String(String::new());
    }
}

impl StructBox for ListLike {
    fn struct_type(&self) -> StructType {
        self.struct_type
    }

    fn handle_char(&mut self, c: char) {
        if c == ',' {
            self.end_chunk();
            return;
        }
        if let Value::String(s) = &mut self.temp {
            s.push(c);
        }
    }

    fn end_chunk(&mut self) {
        self.flush_temp();
    }

    fn post_treatment(&mut self) {
        self.end_chunk();
        if self.data.len() == 1 {
            if let Value::String(s) = &self.data[0] {
                self.data = vec![Value::String(format!(
                    "{start}{s}{end}",
                    start = self.start_char,
                    end = self.end_char
                ))];
            } else if self.data.len() == 1 {
                // unwrap single nested struct
                let _inner = self.data.pop().unwrap();
                return;
            }
        }
    }

    fn accepted_types(&self) -> &'static [StructType] {
        &[
            StructType::None,
            StructType::StringSingle,
            StructType::StringDouble,
            StructType::XmlDict,
            StructType::CurlyDict,
            StructType::List,
            StructType::HookList,
        ]
    }

    fn add_struct(&mut self, child: Box<dyn StructBox>) {
        let val = child.into_value();
        if let Value::String(s) = val {
            if let Value::String(dst) = &mut self.temp {
                if !dst.trim().is_empty() && !s.is_empty() {
                    // ignore random chars before struct in list
                }
                dst.push_str(&s);
            } else {
                self.temp = Value::String(s);
            }
        } else {
            if self.temp.as_str().is_some_and(|t| !t.trim().is_empty()) {
                // ignore chars before struct
            }
            self.temp = val;
        }
    }

    fn into_value(self: Box<Self>) -> Value {
        if self.data.len() == 1 {
            return self.data[0].clone();
        }
        Value::Array(self.data)
    }
}

fn all_types() -> &'static [StructType] {
    &[
        StructType::None,
        StructType::StringSingle,
        StructType::StringDouble,
        StructType::XmlDict,
        StructType::CurlyDict,
        StructType::List,
        StructType::HookList,
    ]
}

fn accepts(current: &dyn StructBox, ty: StructType) -> bool {
    current.accepted_types().contains(&ty) || current.accepted_types() == all_types()
}

fn push_struct(stack: &mut Vec<Box<dyn StructBox>>, ty: StructType) {
    let s: Box<dyn StructBox> = match ty {
        StructType::StringSingle => Box::new(StringSingle::new()),
        StructType::StringDouble => Box::new(StringDouble::new()),
        StructType::XmlDict => Box::new(XmlDict::new(' ', '<', '>', StructType::XmlDict)),
        StructType::CurlyDict => Box::new(XmlDict::new('=', '{', '}', StructType::CurlyDict)),
        StructType::List => Box::new(ListLike::new('(', ')', StructType::List)),
        StructType::HookList => Box::new(ListLike::new('[', ']', StructType::HookList)),
        StructType::None => Box::new(StackBase::new()),
        StructType::MutatedString => Box::new(StackBase::new()),
    };
    stack.push(s);
}

fn end_struct(stack: &mut Vec<Box<dyn StructBox>>) {
    if stack.len() < 2 {
        return;
    }
    let mut child = stack.pop().unwrap();
    child.end_chunk();
    child.post_treatment();
    stack.last_mut().unwrap().add_struct(child);
}

/// Parse an IOReg property value string into JSON (`Value`).
pub fn parse_ioreg_value(line: &str) -> Value {
    let mut stack: Vec<Box<dyn StructBox>> = vec![Box::new(StackBase::new())];
    for c in line.chars() {
        let current_ty = stack
            .last()
            .map(|s| s.struct_type())
            .unwrap_or(StructType::None);
        let top = stack.last().expect("stack");
        match c {
            '<' if accepts(top.as_ref(), StructType::XmlDict) => {
                push_struct(&mut stack, StructType::XmlDict);
            }
            '>' if current_ty == StructType::XmlDict => end_struct(&mut stack),
            '{' if accepts(top.as_ref(), StructType::CurlyDict) => {
                push_struct(&mut stack, StructType::CurlyDict);
            }
            '}' if current_ty == StructType::CurlyDict => end_struct(&mut stack),
            '\'' if current_ty == StructType::StringSingle => {
                end_struct(&mut stack);
            }
            '\'' if accepts(top.as_ref(), StructType::StringSingle) => {
                push_struct(&mut stack, StructType::StringSingle);
            }
            '"' if current_ty == StructType::StringDouble => {
                end_struct(&mut stack);
            }
            '"' if accepts(top.as_ref(), StructType::StringDouble) => {
                push_struct(&mut stack, StructType::StringDouble);
            }
            '[' if accepts(top.as_ref(), StructType::HookList) => {
                push_struct(&mut stack, StructType::HookList);
            }
            ']' if current_ty == StructType::HookList => end_struct(&mut stack),
            '(' if accepts(top.as_ref(), StructType::List) => {
                push_struct(&mut stack, StructType::List);
            }
            ')' if current_ty == StructType::List => end_struct(&mut stack),
            _ => stack.last_mut().unwrap().handle_char(c),
        }
    }
    let mut top = stack.pop().unwrap();
    top.end_chunk();
    top.post_treatment();
    let mut final_val = top.into_value();
    if let Value::String(s) = &final_val {
        if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
            if let Ok(n) = s.parse::<i64>() {
                final_val = json!(n);
            }
        }
    }
    final_val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xml_dict_title() {
        let v = parse_ioreg_value("<class test1, key1 val1>");
        let obj = v.as_object().expect("dict");
        assert_eq!(obj.get("class"), Some(&json!("test1")));
        assert_eq!(obj.get("key1"), Some(&json!("val1")));
    }

    #[test]
    fn parses_quoted_string_with_angle_brackets_and_non_ascii() {
        let v = parse_ioreg_value("\"value -->¿<--\"");
        assert_eq!(v, json!("value -->¿<--"));
    }

    #[test]
    fn parses_quoted_string_with_angle_brackets_and_literal_xbf() {
        let v = parse_ioreg_value("\"value -->\\xbf<--\"");
        assert_eq!(v, json!("value -->\\xbf<--"));
    }
}
