//! Port of SAF `parsers/psthread.py` (`ps_thread.txt`).

use serde_json::{json, Map, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;
use crate::util::{enrich_ps_process_row, parse_cell, snake_case};

const PS_THREAD: &str = "ps_thread.txt";

fn split_fixed_columns_owned(line: &str, ncols: usize) -> Option<Vec<String>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < ncols {
        return None;
    }
    if parts.len() == ncols {
        return Some(parts.into_iter().map(String::from).collect());
    }
    let mut out: Vec<String> = parts[..ncols - 1]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    out.push(parts[ncols - 1..].join(" "));
    Some(out)
}

fn finalize_entry(mut m: Map<String, Value>) -> Value {
    enrich_ps_process_row(&mut m);
    if let (Some(cmd), Some(pid), Some(user)) = (
        m.get("command").and_then(|v| v.as_str()),
        m.get("pid"),
        m.get("user").and_then(|v| v.as_str()),
    ) {
        let pid_s = match pid {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => "?".to_string(),
        };
        m.insert(
            "message".to_string(),
            json!(format!("{cmd} [{pid_s}] as {user}")),
        );
    }
    Value::Object(m)
}

pub struct PsThreadParser;

impl SysdiagnoseParser for PsThreadParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let Some(raw) = archive.get(PS_THREAD) else {
            return Ok(json!({
                "parser": "psthread",
                "source": PS_THREAD,
                "error": "No ps_thread.txt file present",
                "entries": []
            }));
        };

        let text = String::from_utf8_lossy(raw);
        let mut lines = text.lines();
        let Some(header_line) = lines.next() else {
            return Ok(json!({
                "parser": "psthread",
                "source": PS_THREAD,
                "error": "Empty ps_thread.txt",
                "entries": []
            }));
        };

        let header: Vec<String> = header_line.split_whitespace().map(snake_case).collect();
        let header_len = header.len();
        if header_len == 0 {
            return Ok(json!({
                "parser": "psthread",
                "source": PS_THREAD,
                "error": "Missing header",
                "entries": []
            }));
        }

        let mut entries = Vec::new();
        let mut current: Option<Map<String, Value>> = None;

        for line in lines {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }

            // SAF: a process line contains `??` (typically TT or WCHAN).
            if t.contains("??") {
                if let Some(m) = current.take() {
                    entries.push(finalize_entry(m));
                }

                let Some(cells) = split_fixed_columns_owned(t, header_len) else {
                    continue;
                };
                let mut obj = Map::new();
                obj.insert(
                    "timestamp_info".to_string(),
                    json!("sysdiagnose creation time"),
                );
                obj.insert("threads".to_string(), json!(1));
                for (i, key) in header.iter().enumerate() {
                    obj.insert(key.clone(), parse_cell(&cells[i]));
                }
                current = Some(obj);
            } else if let Some(ref mut m) = current {
                let threads = m.get("threads").and_then(|v| v.as_i64()).unwrap_or(1);
                m.insert("threads".to_string(), json!(threads + 1));
            }
        }

        if let Some(m) = current.take() {
            entries.push(finalize_entry(m));
        }

        Ok(json!({
            "parser": "psthread",
            "source": PS_THREAD,
            "entries": entries
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::SysdiagnoseArchive;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn parse_psthread_txt(text: &str) -> Value {
        let mut m = HashMap::new();
        m.insert(
            PS_THREAD.to_string(),
            Arc::from(text.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        PsThreadParser.parse(&arch).expect("psthread parse")
    }

    #[test]
    fn short_name_and_message_for_sshd_tty() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 24May25 0:00.10 sshd: root@ttys000\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 - ttys000 S 24May25 0:00.00 sshd: root@ttys000\n",
        );
        let v = parse_psthread_txt(text);
        let entries = v["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 1);
        let row = &entries[0];
        assert_eq!(row["pid"], 298);
        assert_eq!(row["threads"], 2);
        assert_eq!(row["command"], "sshd: root@ttys000");
        assert_eq!(row["name"], "sshd");
        assert_eq!(row["process_name"], "sshd");
        assert_eq!(
            row["message"].as_str(),
            Some("sshd: root@ttys000 [298] as root")
        );
    }

    #[test]
    fn peels_cpu_time_glued_into_command() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 24May25 0:00.10 sshd: root@ttys000\n",
        );
        let v = parse_psthread_txt(text);
        let row = &v["entries"].as_array().expect("entries")[0];
        assert_eq!(row["command"], "sshd: root@ttys000");
        assert_eq!(row["time"], "0:00.10");
        assert_eq!(row["name"], "sshd");
    }
}
