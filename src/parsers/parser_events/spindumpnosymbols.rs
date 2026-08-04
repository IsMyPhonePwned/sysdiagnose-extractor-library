//! Port of SAF [`spindumpnosymbols.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/src/sysdiagnose/parsers/spindumpnosymbols.py).

use chrono::{DateTime, Duration, FixedOffset};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use crate::util::{parse_process_identity, snake_case, strip_process_name_quotes};

use super::common::saf_event_dict;

const MODULE: &str = "spindumpnosymbols";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanStatus {
    Headers,
    ProcessesRaw,
    Binary,
    Empty,
}

/// Parse one `spindump-nosymbols.txt` body into SAF-shaped events (same pipeline as upstream `parse_file`).
pub fn parse_spindump_nosymbols_text(text: &str) -> Vec<Value> {
    let mut headers: Vec<String> = Vec::new();
    let mut processes_raw: Vec<String> = Vec::new();
    let mut status = ScanStatus::Headers;

    for line in text.lines() {
        let t = line.trim();
        if t == "No samples" {
            status = ScanStatus::Empty;
            break;
        }
        if t.is_empty()
            || t == "Heavy format: stacks are sorted by count"
            || t == "Use -i and -timeline to re-report with chronological sorting"
        {
            continue;
        }
        if t == "------------------------------------------------------------" {
            status = ScanStatus::ProcessesRaw;
            continue;
        }
        if t == "Spindump binary format" {
            status = ScanStatus::Binary;
            continue;
        }
        match status {
            ScanStatus::Headers => headers.push(line.trim().to_string()),
            ScanStatus::ProcessesRaw => processes_raw.push(line.trim().to_string()),
            ScanStatus::Binary | ScanStatus::Empty => {}
        }
    }

    if status == ScanStatus::Empty {
        return Vec::new();
    }

    let Some(mut basic) = try_parse_basic_event(&headers) else {
        return Vec::new();
    };

    if let Some(obj) = basic.as_object_mut() {
        let msg = if let Some(data) = obj.get("data").and_then(|d| d.as_object()) {
            let ds = data
                .get("data_source")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim();
            format!("spindump {ds}")
        } else {
            "spindump".to_string()
        };
        obj.insert("message".into(), json!(msg));
    }

    let start_s = basic
        .get("datetime")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let Some(start) = parse_start_timestamp(&start_s) else {
        return vec![basic];
    };

    let mut events = vec![basic];
    events.extend(parse_processes(&processes_raw, start));
    events
}

fn parse_colon_lines(lines: &[String]) -> Map<String, Value> {
    let mut output = Map::new();
    for line in lines {
        let mut sp = line.splitn(2, ':');
        let key = sp.next().unwrap_or("").trim();
        let val = sp.next().map(str::trim).unwrap_or("");
        if key.is_empty() {
            continue;
        }
        let k = snake_case(key);
        if !k.is_empty() {
            output.insert(k, Value::String(val.to_string()));
        }
    }
    output
}

fn parse_spindump_date_time(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim();
    for fmt in ["%Y-%m-%d %H:%M:%S%.f %z", "%Y-%m-%d %H:%M:%S %z"] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }
    None
}

fn try_parse_basic_event(header_lines: &[String]) -> Option<Value> {
    let mut output = parse_colon_lines(header_lines);
    let dt_str = output.get("date_time").and_then(|v| v.as_str())?;
    let ts = parse_spindump_date_time(dt_str)?;
    output.remove("date_time");
    let data = Value::Object(output);
    Some(saf_event_dict(MODULE, ts, "spindump", "spindump", data))
}

fn parse_start_timestamp(s: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .or_else(|| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f %z").ok())
        .or_else(|| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %z").ok())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcSection {
    Infos,
    Threads,
    Images,
}

fn parse_process(lines: &[String]) -> Option<Map<String, Value>> {
    let mut section = ProcSection::Infos;
    let mut infos: Vec<String> = Vec::new();
    let mut threads: Vec<String> = Vec::new();
    let mut images: Vec<String> = Vec::new();

    for line in lines {
        let t = line.trim();
        if t.contains("Thread 0x") {
            section = ProcSection::Threads;
            threads.push(line.clone());
            continue;
        }
        if t.contains("Binary Images:") {
            section = ProcSection::Images;
            continue;
        }
        match section {
            ProcSection::Infos => infos.push(line.clone()),
            ProcSection::Threads => threads.push(line.clone()),
            ProcSection::Images => images.push(line.clone()),
        }
    }

    let mut process = parse_colon_lines(&infos);
    process.insert("threads".into(), Value::Array(parse_threads(&threads)));
    process.insert("images".into(), Value::Array(parse_images(&images)));

    let proc_line = process.get("process").and_then(|v| v.as_str())?.to_string();
    let (name_only, pid_opt) = parse_process_identity(&proc_line);
    let pid = pid_opt?;
    if name_only.is_empty() {
        return None;
    }
    process.insert("process_line".into(), json!(proc_line));
    process.insert("pid".into(), json!(pid));
    process.insert("process".into(), json!(name_only.clone()));
    process.insert("name".into(), json!(name_only));

    if let Some(parent_val) = process
        .get("parent")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    {
        let (pname, ppid) = parse_process_identity(&parent_val);
        if let Some(ppid) = ppid {
            process.insert("ppid".into(), json!(ppid));
        }
        if !pname.is_empty() {
            process.insert("parent".into(), json!(pname));
        } else {
            process.insert(
                "parent".into(),
                json!(strip_process_name_quotes(
                    parent_val.split('[').next().unwrap_or(&parent_val).trim()
                )),
            );
        }
    }

    let uid_json = match process.get("uid").and_then(|v| v.as_str()) {
        Some(s) => s.parse::<i64>().map(Value::from).unwrap_or(Value::Null),
        None => Value::Null,
    };
    process.insert("uid".into(), uid_json);

    Some(process)
}

fn parse_processes(data: &[String], start_time: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut init = true;
    let mut buf: Vec<String> = Vec::new();

    for line in data {
        let t = line.trim();
        if t.contains("Process:") {
            if !init {
                if let Some(proc) = parse_process(&buf) {
                    push_process_event(&mut out, start_time, proc);
                }
                buf.clear();
                buf.push(line.clone());
            } else {
                init = false;
                buf.push(line.clone());
            }
        } else {
            buf.push(line.clone());
        }
    }

    if let Some(proc) = parse_process(&buf) {
        push_process_event(&mut out, start_time, proc);
    }
    out
}

fn push_process_event(
    out: &mut Vec<Value>,
    start_time: DateTime<FixedOffset>,
    process: Map<String, Value>,
) {
    let sec = process
        .get("time_since_fork")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_end_matches('s').trim().parse::<i64>().ok())
        .flatten();
    let ts = match sec {
        Some(s) => start_time - Duration::seconds(s),
        None => start_time,
    };

    let path = process.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let pname = process
        .get("process")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let chosen = if path.is_empty() { pname } else { path };
    let pid = process.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
    let uid = process.get("uid").cloned().unwrap_or(Value::Null);
    let parent = process
        .get("parent")
        .and_then(|p| p.as_str())
        .unwrap_or(" ");
    let uid_s = match &uid {
        Value::Number(n) => n.to_string(),
        Value::Null => "null".to_string(),
        _ => uid.to_string(),
    };
    let msg = format!("{chosen} [{pid}] as {uid_s} parent={parent}");
    let data = Value::Object(process);
    out.push(saf_event_dict(
        MODULE,
        ts,
        "process running during spindump",
        &msg,
        data,
    ));
}

fn parse_threads(data: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut init = true;
    let mut buf: Vec<String> = Vec::new();

    for line in data {
        if line.trim().contains("Thread 0x") {
            if !init {
                if let Some(th) = parse_thread(&buf) {
                    out.push(th);
                }
                buf.clear();
                buf.push(line.clone());
            } else {
                init = false;
                buf.push(line.clone());
            }
        } else {
            buf.push(line.clone());
        }
    }
    if let Some(th) = parse_thread(&buf) {
        out.push(th);
    }
    out
}

fn parse_thread(data: &[String]) -> Option<Value> {
    let first = data.first()?.trim();
    let thread_hex = thread_id_re()
        .captures(first)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())?;

    let mut obj = Map::new();
    obj.insert("thread".into(), json!(thread_hex));

    if first.contains("DispatchQueue \"") {
        if let Some(c) = Regex::new(r#"DispatchQueue[^"]*\"([^\"]+)\""#)
            .ok()
            .and_then(|re| re.captures(first))
        {
            if let Some(q) = c.get(1) {
                obj.insert("dispatch_queue".into(), json!(q.as_str()));
            }
        }
    }
    if first.contains("Thread name \"") {
        if let Some(c) = Regex::new(r#"Thread name\ \"([^\"]+)\""#)
            .ok()
            .and_then(|re| re.captures(first))
        {
            if let Some(n) = c.get(1) {
                obj.insert("thread_name".into(), json!(n.as_str()));
            }
        }
    }
    if first.contains("priority") {
        if let Some(c) = Regex::new(r"priority\s+([0-9]+)")
            .ok()
            .and_then(|re| re.captures(first))
        {
            if let Some(p) = c.get(1) {
                obj.insert("priority".into(), json!(p.as_str()));
            }
        }
    }
    if first.contains("cpu time") {
        if let Some(c) = Regex::new(r"(?i)cpu\s+time\s+(.*)")
            .ok()
            .and_then(|re| re.captures(first))
        {
            if let Some(t) = c.get(1) {
                obj.insert("cputime".into(), json!(t.as_str().trim()));
            }
        }
    }

    let mut loaded: Vec<Value> = Vec::new();
    let loaded_re = loaded_line_re();
    for line in data.iter().skip(1) {
        let t = line.trim();
        let mut m = Map::new();
        if t.contains('+') {
            if let Some(c) = loaded_re.captures(t) {
                m.insert(
                    "library".into(),
                    json!(c.name("library").map(|x| x.as_str().trim()).unwrap_or("")),
                );
                m.insert(
                    "int".into(),
                    json!(c.name("int").map(|x| x.as_str().trim()).unwrap_or("")),
                );
                m.insert(
                    "hex".into(),
                    json!(c.name("hex").map(|x| x.as_str().trim()).unwrap_or("")),
                );
                if let Some(st) = c
                    .name("status")
                    .map(|x| x.as_str().trim())
                    .filter(|s| !s.is_empty())
                {
                    let cleaned = st.replace(['(', ')'], "").trim().to_string();
                    if !cleaned.is_empty() {
                        m.insert("status".into(), json!(cleaned));
                    }
                }
            }
        } else if !t.contains("truncated backtrace>") {
            if let Some(rest) = t.split('[').nth(1) {
                let hex = rest.trim_end_matches(']').trim();
                if !hex.is_empty() {
                    m.insert("hex".into(), json!(hex));
                }
            }
        }
        loaded.push(Value::Object(m));
    }
    obj.insert("loaded".into(), Value::Array(loaded));
    Some(Value::Object(obj))
}

fn thread_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"Thread\s+(0x[0-9a-fA-F]+)").expect("thread id"))
}

fn loaded_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\((?P<library>[^+]+)\+(?P<int>[^)]+)\)\s+\[(?P<hex>[^\]]+)\](?P<status>.*)")
            .expect("loaded")
    })
}

fn parse_images(data: &[String]) -> Vec<Value> {
    let mut images = Vec::new();
    for line in data {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let clean: Vec<&str> = t.split_whitespace().collect();
        if clean.len() < 5 {
            continue;
        }
        let mut image = Map::new();
        image.insert("start".into(), json!(clean[0]));
        image.insert("end".into(), json!(clean[2]));
        image.insert("image".into(), json!(clean[3]));
        let uuid = clean[4].trim_matches(|c| c == '(' || c == ')');
        image.insert("uuid".into(), json!(uuid));
        if let Some(p) = clean.get(5) {
            image.insert("path".into(), json!(p));
        }
        images.push(Value::Object(image));
    }
    images
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"Date/Time:       2020-01-02 10:00:00 +0000
Data Source:     Stackshots

------------------------------------------------------------
Process:         launchd [1]
Path:            /sbin/launchd
Parent:          kernel_task [0]
UID:             0
Time since fork: 10s

Thread 0x1234 priority 31 cpu time 0.001s
  (libsystem_kernel.dylib+0x123) [0xabc] (running)

Binary Images:
0x1000 - 0x2000  dyld  (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)  /usr/lib/dyld
"#;

    #[test]
    fn spindump_parses_header_and_process_events() {
        let evs = parse_spindump_nosymbols_text(FIXTURE);
        assert!(
            evs.len() >= 2,
            "expected header + process events, got {}",
            evs.len()
        );
        assert_eq!(evs[0].get("module").and_then(|x| x.as_str()), Some(MODULE));
        assert_eq!(
            evs[0].get("timestamp_desc").and_then(|x| x.as_str()),
            Some("spindump")
        );
        assert!(evs[0]
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .starts_with("spindump"),);

        let proc_ev = &evs[1];
        assert_eq!(
            proc_ev.get("timestamp_desc").and_then(|x| x.as_str()),
            Some("process running during spindump")
        );
        let data = proc_ev
            .get("data")
            .and_then(|d| d.as_object())
            .expect("data");
        assert_eq!(data.get("pid").and_then(|x| x.as_i64()), Some(1));
        assert_eq!(
            data.get("process").and_then(|x| x.as_str()),
            Some("launchd")
        );
        assert_eq!(
            data.get("name").and_then(|x| x.as_str()),
            Some("launchd")
        );
        assert_eq!(
            data.get("path").and_then(|x| x.as_str()),
            Some("/sbin/launchd")
        );
    }

    #[test]
    fn spindump_strips_quoted_process_names() {
        let text = r#"Date/Time:       2020-01-02 10:00:00 +0000
Data Source:     Stackshots

------------------------------------------------------------
Process:         "sshd" [298]
Path:            /usr/sbin/sshd
Parent:          "launchd" [1]
UID:             0
Time since fork: 10s

Thread 0x1234 priority 31 cpu time 0.001s
"#;
        let evs = parse_spindump_nosymbols_text(text);
        let proc_ev = evs
            .iter()
            .find(|e| {
                e.get("timestamp_desc").and_then(|t| t.as_str())
                    == Some("process running during spindump")
            })
            .expect("process event");
        let data = proc_ev.get("data").and_then(|d| d.as_object()).unwrap();
        assert_eq!(data.get("process").and_then(|x| x.as_str()), Some("sshd"));
        assert_eq!(data.get("name").and_then(|x| x.as_str()), Some("sshd"));
        assert_eq!(data.get("parent").and_then(|x| x.as_str()), Some("launchd"));
        assert_eq!(data.get("pid").and_then(|x| x.as_i64()), Some(298));
        assert_eq!(data.get("ppid").and_then(|x| x.as_i64()), Some(1));
    }

    #[test]
    fn spindump_no_samples_empty() {
        assert!(parse_spindump_nosymbols_text("No samples\n").is_empty());
    }
}
