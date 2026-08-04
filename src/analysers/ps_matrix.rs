//! Per-PID comparison across ps / psthread / taskinfo / spindump-nosymbols.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

use crate::archive::SysdiagnoseArchive;
use crate::parsers::ParserType;

use super::common::{get_or_parse, pid_from_row, spindump_pid_name_map, ParsedByParser};

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let ps = get_or_parse(archive, parsed, ParserType::ps);
    let psthread = get_or_parse(archive, parsed, ParserType::psthread);
    let taskinfo = get_or_parse(archive, parsed, ParserType::taskinfo);

    let mut ps_by: BTreeMap<i64, Value> = BTreeMap::new();
    if let Some(rows) = ps.get("rows").and_then(|r| r.as_array()) {
        for row in rows {
            if let Some(pid) = pid_from_row(row) {
                ps_by.insert(pid, row.clone());
            }
        }
    }

    let mut pt_by: BTreeMap<i64, Value> = BTreeMap::new();
    if let Some(rows) = psthread.get("entries").and_then(|r| r.as_array()) {
        for row in rows {
            if let Some(pid) = pid_from_row(row) {
                pt_by.insert(pid, row.clone());
            }
        }
    }

    let mut ti_by: BTreeMap<i64, Value> = BTreeMap::new();
    if let Some(events) = taskinfo.get("events").and_then(|r| r.as_array()) {
        for ev in events {
            if let Some(data) = ev.get("data") {
                if let Some(pid) = pid_from_row(data) {
                    ti_by.insert(pid, data.clone());
                }
            }
        }
    }

    let mut spin_by: BTreeMap<i64, String> = BTreeMap::new();
    let spin = get_or_parse(archive, parsed, ParserType::spindumpnosymbols);
    for (pid, name) in spindump_pid_name_map(&spin) {
        spin_by.entry(pid).or_insert(name);
    }

    let mut all_pids: Vec<i64> = ps_by
        .keys()
        .chain(pt_by.keys())
        .chain(ti_by.keys())
        .chain(spin_by.keys())
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    all_pids.sort_unstable();

    let mut matrix = Vec::new();
    for pid in all_pids {
        let ps_val = ps_by.get(&pid).map(|_| "ps").unwrap_or("-");
        let pt_val = pt_by.get(&pid).map(|_| "psthread").unwrap_or("-");
        let ti_val = ti_by.get(&pid).map(|_| "taskinfo").unwrap_or("-");
        let sd_val = spin_by
            .get(&pid)
            .map(|_| "spindumpnosymbols")
            .unwrap_or("-");
        let ps_pid = ps_by.get(&pid).and_then(pid_from_row);
        let pt_pid = pt_by.get(&pid).and_then(pid_from_row);
        let ti_pid = ti_by.get(&pid).and_then(pid_from_row);
        let sd_pid = spin_by.get(&pid).map(|_| pid);
        let pid_consistent = [ps_pid, pt_pid, ti_pid, sd_pid]
            .into_iter()
            .flatten()
            .all(|p| p == pid);
        matrix.push(json!({
            "pid": pid,
            "in_ps": ps_by.contains_key(&pid),
            "in_psthread": pt_by.contains_key(&pid),
            "in_taskinfo": ti_by.contains_key(&pid),
            "in_spindumpnosymbols": spin_by.contains_key(&pid),
            "pid_field_consistent": pid_consistent,
            "ps_command": ps_by.get(&pid).and_then(|r| r.get("command")),
            "psthread_command": pt_by.get(&pid).and_then(|r| r.get("command")),
            "taskinfo_name": ti_by.get(&pid).and_then(|r| r.get("name")),
            "spindump_process": spin_by.get(&pid),
            "sources_present": format!("{ps_val} / {pt_val} / {ti_val} / {sd_val}"),
        }));
    }

    json!({
        "analyser": "ps_matrix",
        "note": "spindumpnosymbols PIDs come from parser jsonl `events` when present, else from raw `Process:` lines in utf8_map output.",
        "rows": matrix,
    })
}
