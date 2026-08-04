//! Port of SAF `parsers/ps.py` (`ps.txt`).

use serde_json::{json, Map, Value};
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::SysdiagnoseParser;
use crate::util::{enrich_ps_process_row, parse_cell, snake_case};

const PS_TXT: &str = "ps.txt";

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

pub struct PsParser;

/// Mirrors SAF [`PsParser.exclude_known_goods`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/src/sysdiagnose/parsers/ps.py):
/// drop rows whose `command` matches any row in `known_good` (compared by `command` only).
pub fn exclude_known_goods(mut processes: Vec<Value>, known_good: &[Value]) -> Vec<Value> {
    let drop_cmd: std::collections::HashSet<String> = known_good
        .iter()
        .filter_map(|row| {
            row.get("command")
                .and_then(|c| c.as_str())
                .map(str::to_owned)
        })
        .collect();
    processes.retain(|row| {
        row.get("command")
            .and_then(|c| c.as_str())
            .map(|cmd| !drop_cmd.contains(cmd))
            .unwrap_or(true)
    });
    processes
}

impl SysdiagnoseParser for PsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let Some(raw) = archive.get(PS_TXT) else {
            return Ok(json!({
                "parser": "ps",
                "source": PS_TXT,
                "error": "No ps.txt file present",
                "rows": []
            }));
        };

        let text = String::from_utf8_lossy(raw);
        let mut lines = text.lines();
        let Some(header_line) = lines.next() else {
            return Ok(json!({
                "parser": "ps",
                "source": PS_TXT,
                "error": "Empty ps.txt",
                "rows": []
            }));
        };

        let header: Vec<String> = header_line.split_whitespace().map(snake_case).collect();
        let header_len = header.len();
        if header_len == 0 {
            return Ok(json!({
                "parser": "ps",
                "source": PS_TXT,
                "error": "Missing ps.txt header",
                "rows": []
            }));
        }

        let mut rows = Vec::new();
        for line in lines {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let Some(cells) = split_fixed_columns_owned(t, header_len) else {
                continue;
            };
            let mut obj = Map::new();
            for (i, key) in header.iter().enumerate() {
                obj.insert(key.clone(), parse_cell(&cells[i]));
            }
            enrich_ps_process_row(&mut obj);
            rows.push(Value::Object(obj));
        }

        Ok(json!({
            "parser": "ps",
            "source": PS_TXT,
            "rows": rows
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::SysdiagnoseArchive;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn parse_ps_txt(text: &str) -> Value {
        let mut m = HashMap::new();
        m.insert(
            PS_TXT.to_string(),
            Arc::from(text.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        PsParser.parse(&arch).expect("ps parse")
    }

    #[test]
    fn parses_sample_ps() {
        let sample = b"USER  PID COMMAND\nroot  1 /sbin/launchd\nmobile  45 /usr/bin/foo bar\n";
        let mut m = HashMap::new();
        m.insert(
            "ps.txt".to_string(),
            Arc::from(sample.to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = PsParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "ps");
        assert_eq!(v["rows"].as_array().unwrap().len(), 2);
        let row0 = &v["rows"][0];
        assert_eq!(row0["user"], "root");
        assert_eq!(row0["pid"], 1);
        let row1 = &v["rows"][1];
        assert_eq!(row1["command"], "/usr/bin/foo bar");
    }

    /// [`test_parse_ps_lower_than_v16`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/test_parsers_ps.py) — tabular `rows` (Rust) vs Python `data` (no jsonl envelope).
    #[test]
    fn upstream_parse_ps_lower_than_v16_rows() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 1 0 0.0 0.4 37 0 4226848 8912 - ?? Ss 14Jan19 7:27.40 /sbin/launchd with space\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        let expected = json!({
            "user": "root",
            "uid": 0,
            "pid": 1,
            "ppid": 0,
            "%cpu": 0.0,
            "%mem": 0.4,
            "pri": 37,
            "ni": 0,
            "vsz": 4226848,
            "rss": 8912,
            "wchan": "-",
            "tt": "??",
            "stat": "Ss",
            "started": "14Jan19",
            "time": "7:27.40",
            "command": "/sbin/launchd with space",
            "command_line": "/sbin/launchd with space",
            "name": "launchd",
            "process": "launchd",
            "process_name": "launchd"
        });
        assert_eq!(row0, &expected);
    }

    /// [`test_parse_ps_newer_than_v16`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/test_parsers_ps.py)
    #[test]
    fn upstream_parse_ps_newer_than_v16_rows() {
        let text = concat!(
            "USER UID PRSNA PID PPID F %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 - 1 0 4004 0.0 0.0 0 0 0 0 - ?? ?s Tue09PM 0:00.00 /sbin/launchd\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        let expected = json!({
            "user": "root",
            "uid": 0,
            "prsna": "-",
            "pid": 1,
            "ppid": 0,
            "f": 4004,
            "%cpu": 0.0,
            "%mem": 0.0,
            "pri": 0,
            "ni": 0,
            "vsz": 0,
            "rss": 0,
            "wchan": "-",
            "tt": "??",
            "stat": "?s",
            "started": "Tue09PM",
            "time": "0:00.00",
            "command": "/sbin/launchd",
            "command_line": "/sbin/launchd",
            "name": "launchd",
            "process": "launchd",
            "process_name": "launchd"
        });
        assert_eq!(row0, &expected);
    }

    #[test]
    fn peels_glued_time_and_short_name_for_sshd_tty() {
        // Header without TIME → CPU time is absorbed into COMMAND.
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 24May25 0:00.10 sshd: root@ttys000\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        assert_eq!(row0["command"], "sshd: root@ttys000");
        assert_eq!(row0["time"], "0:00.10");
        assert_eq!(row0["name"], "sshd");
        assert_eq!(row0["process_name"], "sshd");
        assert_eq!(row0["pid"], 298);
    }

    #[test]
    fn repairs_empty_started_column_shift() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 0:00.10 sshd: root@ttys000\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        assert_eq!(row0["command"], "sshd: root@ttys000");
        assert_eq!(row0["time"], "0:00.10");
        assert_eq!(row0["name"], "sshd");
    }

    /// [`test_ps_exclude_known_goods`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/test_parsers_ps.py)
    #[test]
    fn upstream_exclude_known_goods() {
        let processes = vec![
            json!({"command": "good", "pid": 1}),
            json!({"command": "bad", "pid": 2}),
            json!({"command": "unknown", "pid": 3}),
        ];
        let known_good = vec![json!({"command": "good", "pid": 1})];
        let got = exclude_known_goods(processes, &known_good);
        assert_eq!(
            got,
            vec![
                json!({"command": "bad", "pid": 2}),
                json!({"command": "unknown", "pid": 3}),
            ]
        );
    }
}
