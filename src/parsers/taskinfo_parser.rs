//! Port of SAF `parsers/taskinfo.py` + `utils/tabbasedhierarchy.py` (`taskinfo.txt`).
//!
//! Control flow follows the Python parser, but **without** appending the same `thread ID` line
//! twice (the upstream `if` / `else` structure duplicates that line on every iteration).

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::error::Error;
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;
use crate::tab_hierarchy::parse_block;

const TASKINFO: &str = "taskinfo.txt";

fn num_tasks_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)num tasks:\s*(\d+)").expect("regex"))
}

fn enrich_process(mut block: Value) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let obj = block
        .as_object_mut()
        .ok_or("taskinfo process block is not an object")?;
    let proc_line = obj
        .get("process")
        .and_then(|v| v.as_str())
        .ok_or("taskinfo block missing process field")?
        .to_string();

    let (name, pid_opt) = crate::util::parse_process_identity(&proc_line);
    let pid = pid_opt.ok_or("could not parse pid from process line")?;
    if name.is_empty() {
        return Err("could not parse process name from process line".into());
    }

    // Keep the raw identity for forensics; expose a clean name on `process` / `name`
    // so consumers that promote `process` → `process_name` do not get
    // `"sshd" [298] [unique ID: 298]`.
    obj.insert("process_line".to_string(), json!(proc_line));
    obj.insert("process".to_string(), json!(name.clone()));
    obj.insert("pid".to_string(), json!(pid));
    obj.insert("name".to_string(), json!(name));
    obj.insert("threads".to_string(), json!([]));
    Ok(block)
}

fn run_time_first_seconds(v: &Value) -> Option<u64> {
    let s = v.get("run time").and_then(|x| x.as_str())?;
    s.split_whitespace().next()?.parse().ok()
}

fn maybe_estimated_start(
    acquisition: Option<DateTime<FixedOffset>>,
    process: &Value,
) -> Option<String> {
    let acq = acquisition?;
    let sec = run_time_first_seconds(process)?;
    // SAF subtracts this delta from sysdiagnose time; huge values are not wall-clock seconds.
    const MAX_SANE_RUN_SECONDS: u64 = 86400 * 365 * 30;
    if sec > MAX_SANE_RUN_SECONDS {
        return None;
    }
    let dt = acq - chrono::Duration::seconds(sec as i64);
    Some(dt.to_rfc3339())
}

fn append_thread(
    process: &mut Value,
    extracted: &[String],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let tb = parse_block(extracted);
    let threads = process
        .get_mut("threads")
        .and_then(|t| t.as_array_mut())
        .ok_or("process.threads missing")?;
    threads.push(tb);
    Ok(())
}

pub struct TaskinfoParser;

impl SysdiagnoseParser for TaskinfoParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let Some(raw) = archive.get(TASKINFO) else {
            return Ok(json!({
                "parser": "taskinfo",
                "source": TASKINFO,
                "error": "No taskinfo.txt file present",
                "events": [],
            }));
        };

        let text = String::from_utf8_lossy(raw);
        let lines: Vec<String> = text.lines().map(String::from).collect();
        let line_count = lines.len();
        if line_count == 0 {
            return Ok(json!({
                "parser": "taskinfo",
                "source": TASKINFO,
                "error": "Empty taskinfo.txt",
                "events": [],
            }));
        }

        let acquisition = archive.acquisition();
        let mut events: Vec<Value> = Vec::new();

        if let Some(c) = num_tasks_re().captures(lines[0].trim()) {
            if let Some(n) = c.get(1).and_then(|m| m.as_str().parse::<u64>().ok()) {
                events.push(json!({
                    "timestamp_desc": "taskinfo",
                    "message": format!("{n} tasks/programs running at sysdiagnose creation time."),
                    "data": { "tasks": n }
                }));
            }
        }

        let mut extracted: Vec<String> = Vec::new();
        let mut process: Option<Value> = None;
        let mut n = 1usize;

        while n < lines.len() {
            let line = &lines[n];
            let is_thread_id = line.contains("thread ID:");

            if is_thread_id {
                let prev_threads = n > 0 && lines[n - 1].contains("threads:");
                if prev_threads {
                    let block = parse_block(&extracted);
                    extracted.clear();
                    process = Some(enrich_process(block)?);
                    extracted.push(line.clone());
                } else if let Some(ref mut p) = process {
                    append_thread(p, &extracted)?;
                    extracted.clear();
                    extracted.push(line.clone());
                } else {
                    extracted.push(line.clone());
                }
                n += 1;
                continue;
            }

            if n + 1 < lines.len() && line.trim().is_empty() && lines[n + 1].trim().is_empty() {
                if let Some(mut p) = process.take() {
                    append_thread(&mut p, &extracted)?;
                    extracted.clear();

                    let data = p;
                    let mut event = Map::new();
                    event.insert("timestamp_desc".into(), json!("process start time"));
                    let msg = data
                        .get("name")
                        .or_else(|| data.get("process"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| format!("{s} started"))
                        .unwrap_or_else(|| "process started".to_string());
                    event.insert("message".into(), json!(msg));
                    if let Some(iso) = maybe_estimated_start(acquisition, &data) {
                        event.insert("datetime".into(), json!(iso));
                    }
                    event.insert("data".into(), json!(data));
                    events.push(Value::Object(event));
                } else {
                    extracted.clear();
                }
                n += 2;
                continue;
            }

            extracted.push(line.clone());
            n += 1;
        }

        Ok(json!({
            "parser": "taskinfo",
            "source": TASKINFO,
            "line_count": line_count,
            "acquisition_rfc3339": acquisition.map(|d| d.to_rfc3339()),
            "events": events,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::SysdiagnoseArchive;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn num_tasks_event_without_process_sections() {
        let snippet = "num tasks: 3\n\n";
        let mut m = HashMap::new();
        m.insert(
            TASKINFO.to_string(),
            Arc::from(snippet.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TaskinfoParser.parse(&arch).unwrap();
        let ev = v["events"].as_array().unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["data"]["tasks"], 3);
    }

    #[test]
    fn process_name_is_clean_not_raw_identity_line() {
        // Minimal taskinfo process block: process line + threads header + one thread + blank blank.
        let snippet = concat!(
            "num tasks: 1\n",
            "process: \"sshd\" [298] [unique ID: 298]\n",
            "run time: 10 secs\n",
            "threads: 1\n",
            "thread ID: 0x1\n",
            "\n",
            "\n",
        );
        let mut m = HashMap::new();
        m.insert(
            TASKINFO.to_string(),
            Arc::from(snippet.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TaskinfoParser.parse(&arch).unwrap();
        let ev = v["events"].as_array().unwrap();
        let proc = ev
            .iter()
            .find(|e| e["timestamp_desc"] == "process start time")
            .expect("process event");
        assert_eq!(proc["data"]["name"], "sshd");
        assert_eq!(proc["data"]["process"], "sshd");
        assert_eq!(proc["data"]["pid"], 298);
        assert_eq!(
            proc["data"]["process_line"],
            "\"sshd\" [298] [unique ID: 298]"
        );
        assert_eq!(proc["message"], "sshd started");
        assert!(!proc["message"]
            .as_str()
            .unwrap_or("")
            .contains("unique ID"));
    }
}
