//! Behaviour and API tests for analysers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::json;
use strum::IntoEnumIterator;

use crate::SysdiagnoseArchive;

use super::{all_analyser_types, analyser_for, AnalyserType, ParsedByParser};

fn archive_with(files: &[(&str, &[u8])]) -> SysdiagnoseArchive {
    let mut m = HashMap::new();
    for (path, bytes) in files {
        m.insert(
            path.to_string(),
            Arc::from(bytes.to_vec().into_boxed_slice()),
        );
    }
    SysdiagnoseArchive::from_files_for_test(m)
}

#[test]
fn analyser_from_str_roundtrip() {
    let ids = [
        "accounts",
        "apps",
        "coverage",
        "file_stats",
        "install_enrichment",
        "mcstateshared",
        "network_iocs",
        "permissions",
        "plist",
        "ps_everywhere",
        "ps_matrix",
        "summary",
        "timesketch",
        "wifi_geolocation",
        "wifi_geolocation_kml",
    ];
    for s in ids {
        let t: AnalyserType = s.parse().expect(s);
        assert_eq!(t.as_str(), s, "as_str for {s}");
        let t2: AnalyserType = t.as_str().parse().expect("as_str parse");
        assert_eq!(t, t2);
    }
}

#[test]
fn analyser_from_str_rejects_unknown() {
    assert!("not_an_analyser".parse::<AnalyserType>().is_err());
}

#[test]
fn all_analyser_types_matches_enum_iter() {
    let mut from_fn: Vec<_> = all_analyser_types();
    from_fn.sort_by_key(|a| a.as_str());
    let mut from_iter: Vec<_> = AnalyserType::iter().collect();
    from_iter.sort_by_key(|a| a.as_str());
    assert_eq!(from_fn, from_iter);
    let names: HashSet<_> = from_iter.iter().map(|a| a.as_str()).collect();
    assert_eq!(names.len(), 14);
}

#[test]
fn coverage_reflects_parsed_keys() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert("ps".to_string(), json!({"parser": "ps", "rows": []}));
    parsed.insert("sys".to_string(), json!({"parser": "sys"}));
    let v = analyser_for(AnalyserType::coverage)
        .analyse(&arch, &parsed)
        .expect("coverage");
    assert_eq!(v["analyser"], "coverage");
    assert_eq!(v["parser_types_total"], crate::all_parser_types().len());
    let present = v["parser_keys_present"].as_array().expect("present");
    assert_eq!(present.len(), 2);
}

#[test]
fn ps_matrix_aligns_injected_ps_psthread_taskinfo() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "ps".to_string(),
        json!({
            "parser": "ps",
            "rows": [{"user": "root", "pid": 1, "command": "/sbin/launchd"}]
        }),
    );
    parsed.insert(
        "psthread".to_string(),
        json!({
            "parser": "psthread",
            "entries": [{"user": "root", "pid": 1, "command": "/sbin/launchd"}]
        }),
    );
    parsed.insert(
        "taskinfo".to_string(),
        json!({
            "parser": "taskinfo",
            "events": [{"data": {"pid": 1, "name": "/sbin/launchd"}}]
        }),
    );
    let v = analyser_for(AnalyserType::ps_matrix)
        .analyse(&arch, &parsed)
        .expect("ps_matrix");
    assert_eq!(v["analyser"], "ps_matrix");
    let rows = v["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["pid"], 1);
    assert_eq!(row["in_ps"], true);
    assert_eq!(row["in_psthread"], true);
    assert_eq!(row["in_taskinfo"], true);
    assert_eq!(row["in_spindumpnosymbols"], false);
    assert_eq!(row["pid_field_consistent"], true);
    assert_eq!(row["sources_present"], "ps / psthread / taskinfo / -");
}

#[test]
fn timesketch_includes_shutdown_event_with_datetime() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "shutdownlogs".to_string(),
        json!({
            "parser": "shutdownlogs",
            "events": [{
                "datetime": "2020-01-02T03:04:05+00:00",
                "message": "foo is still there during shutdown after 1s",
                "timestamp_desc": "process running at shutdown",
                "data": { "pid": 42, "command": "foo" }
            }]
        }),
    );
    let v = analyser_for(AnalyserType::timesketch)
        .analyse(&arch, &parsed)
        .expect("timesketch");
    assert_eq!(v["analyser"], "timesketch");
    let events = v["events"].as_array().expect("events");
    assert!(
        events.iter().any(|e| {
            e["sysdiagnose_parser"] == "shutdownlogs"
                && e["datetime"] == "2020-01-02T03:04:05+00:00"
                && e["time_is_approximate"] == false
        }),
        "expected shutdownlogs event: {events:?}"
    );
    let csv = v["csv"].as_str().expect("csv");
    assert!(csv.contains("2020-01-02T03:04:05+00:00"));
    assert!(csv.contains("shutdownlogs"));

    let jsonl = v["jsonl"].as_str().expect("jsonl");
    assert!(
        jsonl.lines().any(|line| {
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
                return false;
            };
            ev["sysdiagnose_parser"] == "shutdownlogs"
                && ev["datetime"] == "2020-01-02T03:04:05+00:00"
        }),
        "expected shutdownlogs line in jsonl: {jsonl:?}"
    );
}

#[test]
fn ps_everywhere_picks_up_injected_ps_rows() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "ps".to_string(),
        json!({
            "parser": "ps",
            "rows": [{"user": "root", "pid": 1, "command": "/usr/libexec/foo --bar"}]
        }),
    );
    let v = analyser_for(AnalyserType::ps_everywhere)
        .analyse(&arch, &parsed)
        .expect("ps_everywhere");
    assert_eq!(v["analyser"], "ps_everywhere");
    let n = v["count"].as_u64().expect("count");
    assert!(n >= 1);
    let entries = v["entries"].as_array().expect("entries");
    let ps_row = entries
        .iter()
        .find(|e| e["source"] == "ps")
        .expect("ps-sourced entry");
    assert_eq!(ps_row["pid"], 1);
    assert_eq!(ps_row["user"], "root");
    assert_eq!(ps_row["command"], "/usr/libexec/foo --bar");
    assert!(ps_row["sources"].as_array().is_some());
}

#[test]
fn ps_everywhere_merges_taskinfo_and_spindump_fields_by_pid() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "ps".to_string(),
        json!({
            "parser": "ps",
            "rows": [{
                "user": "root",
                "uid": 0,
                "pid": 298,
                "ppid": 1,
                "command": "sshd: root@ttys000"
            }]
        }),
    );
    parsed.insert(
        "taskinfo".to_string(),
        json!({
            "parser": "taskinfo",
            "events": [{
                "datetime": "2023-05-24T20:27:46Z",
                "timestamp_desc": "process start time",
                "message": "sshd started",
                "data": {
                    "name": "sshd",
                    "process": "sshd",
                    "pid": 298,
                    "run time": "92 s",
                    "threads": [{"thread ID": "0x1"}]
                }
            }]
        }),
    );
    parsed.insert(
        "spindumpnosymbols".to_string(),
        json!({
            "parser": "spindumpnosymbols",
            "format": "jsonl",
            "events": [{
                "datetime": "2023-05-24T20:28:00Z",
                "timestamp_desc": "process running during spindump",
                "message": "/usr/sbin/sshd [298] as 0 parent=launchd",
                "data": {
                    "process": "sshd",
                    "pid": 298,
                    "uid": 0,
                    "parent": "launchd [1]",
                    "path": "/usr/sbin/sshd",
                    "footprint": "1840 KB",
                    "time_since_fork": "89s",
                    "threads": [{"thread": "0x11a9"}]
                }
            }]
        }),
    );

    let v = analyser_for(AnalyserType::ps_everywhere)
        .analyse(&arch, &parsed)
        .expect("ps_everywhere");
    let entries = v["entries"].as_array().expect("entries");
    let row = entries
        .iter()
        .find(|e| e["pid"] == 298)
        .expect("merged sshd row");
    assert_eq!(row["user"], "root");
    assert_eq!(row["uid"], 0);
    assert_eq!(row["ppid"], 1);
    assert_eq!(row["run time"], "92 s");
    assert_eq!(row["path"], "/usr/sbin/sshd");
    assert_eq!(row["footprint"], "1840 KB");
    assert_eq!(row["time_since_fork"], "89s");
    assert_eq!(row["datetime"], "2023-05-24T20:27:46Z");
    assert_eq!(row["threads"], 1);
    assert!(row["sources"].as_array().is_some_and(|a| a.len() >= 3));
}

#[test]
fn ps_everywhere_backfills_args_onto_taskinfo_by_path() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "ps".to_string(),
        json!({
            "parser": "ps",
            "rows": [{
                "user": "mobile",
                "pid": 461,
                "command": "/var/containers/Bundle/Application/4B6E715E-641B-4F43-B39B-CA9AE3E8B73B/Signal.app/mussel dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg=="
            }]
        }),
    );
    parsed.insert(
        "taskinfo".to_string(),
        json!({
            "parser": "taskinfo",
            "format": "jsonl",
            "events": [{
                "datetime": "2025-04-07T14:47:00Z",
                "message": "mussel started",
                "timestamp_desc": "process start time",
                "data": {
                    "name": "mussel",
                    "process": "mussel",
                    "pid": 279,
                    "ppid": 1,
                    "path": "/private/var/containers/Bundle/Application/4B6E715E-641B-4F43-B39B-CA9AE3E8B73B/Signal.app/mussel",
                    "parent": "launchd"
                }
            }]
        }),
    );

    let v = analyser_for(AnalyserType::ps_everywhere)
        .analyse(&arch, &parsed)
        .expect("ps_everywhere");
    let entries = v["entries"].as_array().expect("entries");
    let taskinfo_row = entries
        .iter()
        .find(|e| e["pid"] == 279)
        .expect("taskinfo mussel");
    assert_eq!(taskinfo_row["process_name"], "mussel");
    assert_eq!(
        taskinfo_row["args"],
        "dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg=="
    );
    let ps_row = entries
        .iter()
        .find(|e| e["pid"] == 461)
        .expect("ps mussel");
    assert_eq!(ps_row["args"], "dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==");
    assert_eq!(ps_row["process_name"], "mussel");
}

#[test]
fn ps_everywhere_backfills_parent_name_from_ppid() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "ps".to_string(),
        json!({
            "parser": "ps",
            "rows": [
                {
                    "user": "root",
                    "pid": 298,
                    "command": "sshd: root@ttys000"
                },
                {
                    "user": "mobile",
                    "pid": 410,
                    "ppid": 298,
                    "command": "/usr/bin/zsh"
                }
            ]
        }),
    );

    let v = analyser_for(AnalyserType::ps_everywhere)
        .analyse(&arch, &parsed)
        .expect("ps_everywhere");
    let entries = v["entries"].as_array().expect("entries");
    let row = entries
        .iter()
        .find(|e| e["pid"] == 410)
        .expect("merged zsh row");
    assert_eq!(row["ppid"], 298);
    assert_eq!(row["parent_pid"], 298);
    assert_eq!(row["parent"], "sshd");
}

#[test]
fn file_stats_groups_by_top_level_path() {
    let arch = archive_with(&[
        ("logs/a.txt", b"1"),
        ("logs/b.txt", b"2"),
        ("WiFi/x.txt", b"3"),
    ]);
    let v = analyser_for(AnalyserType::file_stats)
        .analyse(&arch, &ParsedByParser::new())
        .expect("file_stats");
    assert_eq!(v["analyser"], "file_stats");
    assert_eq!(v["archive_total_files"], 3);
    let by = v["by_top_level_segment"].as_object().expect("by");
    assert_eq!(by.get("logs").and_then(|x| x.as_u64()), Some(2));
    assert_eq!(by.get("WiFi").and_then(|x| x.as_u64()), Some(1));
    assert!(v.get("by_directory").and_then(|x| x.as_array()).is_some());
}

#[test]
fn wifi_gpx_is_well_formed_empty_without_networks() {
    let arch = archive_with(&[]);
    let v = analyser_for(AnalyserType::wifi_geolocation)
        .analyse(&arch, &ParsedByParser::new())
        .expect("wifi_geolocation");
    assert_eq!(v["analyser"], "wifi_geolocation");
    let xml = v["xml"].as_str().expect("xml");
    assert!(xml.contains("<gpx"));
    assert!(xml.contains("</gpx>"));
}

#[test]
fn wifi_kml_is_well_formed_empty_without_networks() {
    let arch = archive_with(&[]);
    let v = analyser_for(AnalyserType::wifi_geolocation_kml)
        .analyse(&arch, &ParsedByParser::new())
        .expect("wifi_kml");
    assert_eq!(v["analyser"], "wifi_geolocation_kml");
    let xml = v["xml"].as_str().expect("xml");
    assert!(xml.contains("<kml"));
    assert!(xml.contains("</kml>"));
}

#[test]
fn summary_returns_markdown_content() {
    let arch = archive_with(&[]);
    let v = analyser_for(AnalyserType::summary)
        .analyse(&arch, &ParsedByParser::new())
        .expect("summary");
    assert_eq!(v["analyser"], "summary");
    assert_eq!(v["format"], "markdown");
    let s = v["content"].as_str().expect("content");
    assert!(s.contains("Device"));
    assert!(s.contains("## Shutdown clients"));
    assert!(s.contains("## Security / keychain"));
}

#[test]
fn summary_security_and_shutdown_insights_with_parsed_stub() {
    let arch = archive_with(&[]);
    let mut parsed: ParsedByParser = HashMap::new();
    parsed.insert(
        "security_sysdiagnose".to_string(),
        json!({
            "parser": "security_sysdiagnose",
            "format": "jsonl",
            "events": [{
                "message": "Keychain access sample event",
                "data": { "section": "genp", "attributes": {} }
            }]
        }),
    );
    parsed.insert(
        "shutdownlogs".to_string(),
        json!({
            "parser": "shutdownlogs",
            "events": [{
                "datetime": "2021-05-06T12:00:00+00:00",
                "message": "x",
                "data": {
                    "pid": 1,
                    "command": "/Volumes/foo",
                    "time_waiting": 3.5,
                    "uuid": "U1"
                }
            }]
        }),
    );
    let v = analyser_for(AnalyserType::summary)
        .analyse(&arch, &parsed)
        .expect("summary");
    let s = v["content"].as_str().expect("content");
    assert!(s.contains("## Shutdown clients"));
    assert!(s.contains("security-sysdiagnose"));
    assert!(s.contains("Keychain"));
    assert!(s.contains("| 1 |"));
    assert!(s.contains("/Volumes/foo"));
}

#[test]
fn mcstateshared_lists_stub_files_from_archive() {
    let arch = archive_with(&[(
        "logs/MCState/Shared/profile-test.stub",
        b"PayloadIdentifier: test.profile\n",
    )]);
    let v = analyser_for(AnalyserType::mcstateshared)
        .analyse(&arch, &ParsedByParser::new())
        .expect("mcstateshared");
    assert_eq!(v["analyser"], "mcstateshared");
    let rows = v["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["path"]
        .as_str()
        .unwrap()
        .contains("profile-test.stub"));
}

#[test]
fn every_analyser_runs_ok_on_minimal_inputs() {
    let arch = archive_with(&[("dummy.txt", b"x")]);
    let parsed = ParsedByParser::new();
    for t in AnalyserType::iter() {
        let v = analyser_for(t)
            .analyse(&arch, &parsed)
            .unwrap_or_else(|e| panic!("analyser {} failed: {e}", t.as_str()));
        assert_eq!(
            v.get("analyser").and_then(|x| x.as_str()),
            Some(t.as_str()),
            "analyser field for {}",
            t.as_str()
        );
    }
}
