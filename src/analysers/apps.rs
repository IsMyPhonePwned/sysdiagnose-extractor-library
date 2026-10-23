//! Installed-app / bundle-ID aggregation across parsers.
//!
//! Preferred source set mirrors mobipwn Packages (`packagesQuery`):
//! `mobileinstallation`, `appinstallation`, `accessibility_tcc`, `itunesstore`,
//! `mobilebackup`, powerlogs **App Info** rows, and `itunesmetadata` plists.
//!
//! When Apollo powerlogs events are empty (browser WASM historically stubbed
//! SQLite), App Info is read directly from `PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS`
//! via [`crate::sqlite_dump`]. brctl / logdata mines run only if the inventory is
//! still empty after preferred sources.

use serde_json::{json, Map, Value};
use std::sync::Arc;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::ParserType;
use crate::sqlite_dump::query_sqlite_select;

use super::common::{
    brctl_match_context, bundle_id_re, extract_app_bundle_id_from_text, for_each_sqlite_row,
    get_or_parse, merge_app, merge_mvt_plist_bundle_signals, sqlite_row_apps_excerpt,
    tcc_client_and_service, truncate_json_string, value_looks_like_hard_error, ParsedByParser,
    APPS_MAX_HITS_PER_APP,
};

const POWERLOG_APP_INFO_SQL: &str = r#"
SELECT
    TIMESTAMP,
    APPNAME AS "app name",
    APPEXECUTABLE AS "app executable name",
    APPBUNDLEID AS "bundle id",
    APPBUILDVERSION AS "app build version",
    APPBUNDLEVERSION AS "app bundle version",
    APPTYPE AS "app type",
    APPDELETEDDATE AS "app deleted date raw",
    ID AS "allapps_id"
FROM PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
"#;

const POWERLOG_APP_INFO_SQL_MINIMAL: &str = r#"
SELECT
    TIMESTAMP,
    APPNAME AS "app name",
    APPBUNDLEID AS "bundle id",
    APPDELETEDDATE AS "app deleted date raw",
    ID AS "allapps_id"
FROM PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
"#;

const POWERLOG_DB_PATTERNS: &[&str] = &[
    "logs/powerlogs/powerlog_*",
    "logs/powerlogs/log_*",
    "logs/powerlogs/CurrentPowerlog.PLSQL",
    "**/CurrentPowerlog.PLSQL",
];

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let mut apps: Map<String, Value> = Map::new();
    let mut app_info_hits = 0usize;
    let mut tcc_hits = 0usize;

    let tcc = get_or_parse(archive, parsed, ParserType::accessibility_tcc);
    if !value_looks_like_hard_error(&tcc) {
        for_each_sqlite_row(&tcc, |rm, sqlite_db, sqlite_table| {
            if let Some((c, service)) = tcc_client_and_service(rm) {
                let mut extra = Map::new();
                if let Some(s) = service {
                    extra.insert("service".into(), json!(s));
                }
                if let Some(a) = rm
                    .get("allowed")
                    .or_else(|| rm.get("auth_value"))
                    .cloned()
                {
                    extra.insert("allowed".into(), a);
                }
                extra.insert("sqlite_db".into(), json!(sqlite_db));
                extra.insert("sqlite_table".into(), json!(sqlite_table));
                extra.insert("row".into(), sqlite_row_apps_excerpt(rm));
                merge_app(&mut apps, c, "accessibility_tcc", Value::Object(extra));
                tcc_hits += 1;
            }
        });
    }

    let itunes = get_or_parse(archive, parsed, ParserType::itunesstore);
    if !value_looks_like_hard_error(&itunes) {
        for_each_sqlite_row(&itunes, |rm, sqlite_db, sqlite_table| {
            for key in ["bundle_id", "application_id"] {
                if let Some(b) = rm.get(key).and_then(|v| v.as_str()).map(str::trim) {
                    if !b.is_empty() {
                        merge_app(
                            &mut apps,
                            b.to_string(),
                            "itunesstore",
                            json!({
                                "sqlite_db": sqlite_db,
                                "sqlite_table": sqlite_table,
                                "matched_column": key,
                                "row": sqlite_row_apps_excerpt(rm),
                            }),
                        );
                    }
                }
            }
        });
    }

    let appinst = get_or_parse(archive, parsed, ParserType::appinstallation);
    if !value_looks_like_hard_error(&appinst) {
        for_each_sqlite_row(&appinst, |rm, sqlite_db, sqlite_table| {
            let excerpt = sqlite_row_apps_excerpt(rm);
            let mut seen = false;
            for key in ["bundle_id", "bundle id", "application_id", "zbundlename"] {
                if let Some(b) = rm.get(key).and_then(|v| v.as_str()).map(str::trim) {
                    if b.is_empty() {
                        continue;
                    }
                    seen = true;
                    merge_app(
                        &mut apps,
                        b.to_string(),
                        "appinstallation",
                        json!({
                            "sqlite_db": sqlite_db,
                            "sqlite_table": sqlite_table,
                            "matched_column": key,
                            "row": excerpt.clone(),
                        }),
                    );
                }
            }
            if seen {
                return;
            }
            for (col, val) in rm {
                let Some(s) = val.as_str() else { continue };
                if let Some(bid) = extract_app_bundle_id_from_text(s) {
                    merge_app(
                        &mut apps,
                        bid,
                        "appinstallation",
                        json!({
                            "sqlite_db": sqlite_db,
                            "sqlite_table": sqlite_table,
                            "matched_column": col,
                            "matched_in": "cell_text",
                            "message": truncate_json_string(s, 400),
                            "row": excerpt.clone(),
                        }),
                    );
                }
            }
        });
    }

    let mobile = get_or_parse(archive, parsed, ParserType::mobileinstallation);
    if !value_looks_like_hard_error(&mobile) {
        let mut mined_from_events = false;
        if let Some(events) = mobile.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                let data = ev.get("data").and_then(|d| d.as_object());
                let msg = ev
                    .get("message")
                    .and_then(|v| v.as_str())
                    .or_else(|| data.and_then(|d| d.get("message")).and_then(|v| v.as_str()))
                    .unwrap_or("");
                let bid = data
                    .and_then(|d| {
                        d.get("bundle_id")
                            .or_else(|| d.get("bundle id"))
                            .or_else(|| d.get("BundleID"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                    })
                    .or_else(|| extract_app_bundle_id_from_text(msg));
                let Some(bid) = bid else {
                    continue;
                };
                mined_from_events = true;
                let mut extra = Map::new();
                if !msg.is_empty() {
                    extra.insert("message".into(), json!(truncate_json_string(msg, 400)));
                    extra.insert(
                        "match_context".into(),
                        json!(truncate_json_string(msg, 240)),
                    );
                }
                if let Some(dt) = ev.get("datetime").cloned() {
                    extra.insert("datetime".into(), dt);
                } else if let Some(ts) = ev.get("timestamp").cloned() {
                    extra.insert("datetime".into(), ts);
                }
                if let Some(d) = data {
                    for k in [
                        "short_version",
                        "CFBundleShortVersionString",
                        "version",
                        "CFBundleVersion",
                        "source_file",
                        "path",
                    ] {
                        if let Some(v) = d.get(k) {
                            extra.insert(k.to_string(), v.clone());
                        }
                    }
                    extra.insert("row".into(), sqlite_row_apps_excerpt(d));
                }
                merge_app(&mut apps, bid, "mobileinstallation", Value::Object(extra));
            }
        }
        // Legacy / test shape: `{ "logs/...": "raw log text" }` when events are absent.
        if !mined_from_events {
            if let Value::Object(paths) = mobile.as_ref() {
                for (path, val) in paths {
                    let Value::String(text) = val else {
                        continue;
                    };
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        let Some(bid) = extract_app_bundle_id_from_text(line) else {
                            continue;
                        };
                        let mut extra = Map::new();
                        extra.insert("source_file".into(), json!(path));
                        extra.insert("message".into(), json!(truncate_json_string(line, 400)));
                        extra.insert(
                            "match_context".into(),
                            json!(truncate_json_string(line, 240)),
                        );
                        if let Some(dt) = mi_line_leading_datetime(line) {
                            extra.insert("datetime".into(), json!(dt));
                        }
                        merge_app(&mut apps, bid, "mobileinstallation", Value::Object(extra));
                    }
                }
            }
        }
    }

    let powerlogs = get_or_parse(archive, parsed, ParserType::powerlogs);
    if !value_looks_like_hard_error(&powerlogs) {
        // Mobipwn Packages: powerlogs App Info inventory (apollo powerlog_app_info).
        // Prefer structured `bundle id` on the row — Apollo messages often omit it.
        for_each_sqlite_row(&powerlogs, |rm, sqlite_db, sqlite_table| {
            let msg = rm
                .get("message")
                .or_else(|| rm.get("Message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let module = rm
                .get("apollo_module")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let is_app_info = module == "powerlog_app_info"
                || msg.contains("App Info:")
                || (rm.get("app name").is_some() && rm.get("bundle id").is_some());
            if !is_app_info {
                return;
            }
            let bid = rm
                .get("bundle id")
                .or_else(|| rm.get("BUNDLE ID"))
                .or_else(|| rm.get("bundle_id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .or_else(|| extract_app_bundle_id_from_text(msg))
                .or_else(|| {
                    msg.split_once("bundle id=")
                        .or_else(|| msg.split_once("bundle ID="))
                        .or_else(|| msg.split_once("Bundle ID="))
                        .map(|(_, rest)| {
                            rest.split([',', ' ', '\t', '\n'])
                                .next()
                                .unwrap_or("")
                                .trim()
                                .to_string()
                        })
                        .filter(|s| !s.is_empty())
                });
            let Some(bid) = bid else { return };
            let mut extra = Map::new();
            extra.insert("sqlite_db".into(), json!(sqlite_db));
            extra.insert("sqlite_table".into(), json!(sqlite_table));
            extra.insert("matched_in".into(), json!("app_info_message"));
            extra.insert("row".into(), sqlite_row_apps_excerpt(rm));
            if !msg.is_empty() {
                extra.insert("message".into(), json!(truncate_json_string(msg, 800)));
            }
            if let Some(v) = rm.get("datetime").or_else(|| rm.get("timestamp")) {
                extra.insert("datetime".into(), v.clone());
            }
            for k in [
                "app name",
                "app executable name",
                "app bundle version",
                "app build version",
                "app deleted date",
                "app type",
                "bundle id",
            ] {
                if let Some(v) = rm.get(k) {
                    extra.insert(k.to_string(), v.clone());
                }
            }
            merge_app(&mut apps, bid, "powerlogs", Value::Object(extra));
            app_info_hits += 1;
        });
    }

    let mobilebackup = get_or_parse(archive, parsed, ParserType::mobilebackup);
    if !value_looks_like_hard_error(&mobilebackup) {
        if let Value::Object(paths) = mobilebackup.as_ref() {
            for (path, val) in paths {
                merge_mvt_plist_bundle_signals(val, &mut apps, "mobilebackup", Some(path.as_str()));
            }
        }
    }

    let plists = get_or_parse(archive, parsed, ParserType::plists);
    if !value_looks_like_hard_error(&plists) {
        if let Some(files) = plists.get("files").and_then(|f| f.as_object()) {
            for (path, val) in files {
                if !path.to_ascii_lowercase().contains("itunesmetadata.plist") {
                    continue;
                }
                merge_mvt_plist_bundle_signals(
                    val,
                    &mut apps,
                    "plists_itunes_metadata",
                    Some(path.as_str()),
                );
            }
        }
    }

    // Apollo powerlogs may be empty on WASM (no rusqlite Apollo path). Read App Info
    // directly from the powerlog SQLite table — same source mobipwn Packages uses.
    let mut app_info_direct = 0usize;
    if app_info_hits == 0 {
        app_info_direct = mine_powerlog_app_info_from_archive(archive, &mut apps);
        app_info_hits += app_info_direct;
    }

    // Last resort only: do not pollute a real inventory with brctl/logdata noise.
    let used_wasm_fallback = if apps.is_empty() {
        mine_brctl_bundle_ids(parsed, archive, &mut apps);
        mine_logdata_bundle_ids(parsed, archive, &mut apps);
        !apps.is_empty()
    } else {
        false
    };

    let count = apps.len();
    let note = if used_wasm_fallback {
        "Preferred Packages sources were empty. Fell back to brctl + logdata bundle-id mines (weak evidence)."
    } else if app_info_direct > 0 {
        "Inventory includes powerlogs App Info read directly from PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS (mobipwn Packages primary source)."
    } else {
        "Inventory mirrors mobipwn Packages: mobileinstallation, appinstallation, accessibility_tcc, itunesstore, mobilebackup, powerlogs App Info, itunesmetadata plists."
    };
    json!({
        "analyser": "apps",
        "apps": Value::Object(apps),
        "count": count,
        "hits_cap_per_app": APPS_MAX_HITS_PER_APP,
        "app_info_hits": app_info_hits,
        "app_info_direct_hits": app_info_direct,
        "tcc_hits": tcc_hits,
        "wasm_text_fallback": used_wasm_fallback,
        "note": note
    })
}

fn row_field_ci<'a>(rm: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for want in keys {
        let want_l = want.to_ascii_lowercase();
        for (k, v) in rm {
            if k.to_ascii_lowercase() == want_l {
                return Some(v);
            }
        }
    }
    None
}

fn row_str_ci(rm: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    let v = row_field_ci(rm, keys)?;
    if let Some(s) = v.as_str() {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
        return None;
    }
    if let Some(n) = v.as_i64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_u64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_f64() {
        return Some(n.to_string());
    }
    None
}

fn format_app_deleted_date(raw: Option<&Value>) -> String {
    let Some(v) = raw else {
        return "NOT DELETED".into();
    };
    let secs = if let Some(n) = v.as_i64() {
        n
    } else if let Some(n) = v.as_u64() {
        n as i64
    } else if let Some(s) = v.as_str() {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("not deleted") || t == "0" {
            return "NOT DELETED".into();
        }
        if let Ok(n) = t.parse::<i64>() {
            n
        } else {
            return t.to_string();
        }
    } else {
        return "NOT DELETED".into();
    };
    if secs <= 0 {
        return "NOT DELETED".into();
    }
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn merge_app_info_row(
    apps: &mut Map<String, Value>,
    rm: &Map<String, Value>,
    sqlite_db: &str,
) -> bool {
    let bid = row_str_ci(rm, &["bundle id", "APPBUNDLEID", "bundle_id"])
        .or_else(|| {
            row_str_ci(rm, &["message"]).and_then(|m| extract_app_bundle_id_from_text(&m))
        });
    let Some(bid) = bid else {
        return false;
    };

    let mut extra = Map::new();
    extra.insert("sqlite_db".into(), json!(sqlite_db));
    extra.insert("sqlite_table".into(), json!("powerlog_app_info"));
    extra.insert("matched_in".into(), json!("app_info_direct"));
    extra.insert("apollo_module".into(), json!("powerlog_app_info"));
    extra.insert("row".into(), Value::Object(rm.clone()));

    for (out_key, keys) in [
        ("app name", &["app name", "APPNAME"][..]),
        (
            "app executable name",
            &["app executable name", "APPEXECUTABLE"][..],
        ),
        (
            "app bundle version",
            &["app bundle version", "APPBUNDLEVERSION"][..],
        ),
        (
            "app build version",
            &["app build version", "APPBUILDVERSION"][..],
        ),
        ("app type", &["app type", "APPTYPE"][..]),
        ("bundle id", &["bundle id", "APPBUNDLEID"][..]),
    ] {
        if let Some(v) = row_field_ci(rm, keys) {
            extra.insert(out_key.into(), v.clone());
        }
    }

    let deleted = format_app_deleted_date(row_field_ci(
        rm,
        &["app deleted date raw", "APPDELETEDDATE", "app deleted date"],
    ));
    extra.insert("app deleted date".into(), json!(deleted));

    if let Some(ts) = row_field_ci(rm, &["TIMESTAMP", "timestamp", "datetime"]) {
        if let Some(n) = ts.as_i64().or_else(|| ts.as_u64().map(|u| u as i64)) {
            if n > 1_000_000_000 {
                if let Some(dt) = chrono::DateTime::from_timestamp(n, 0) {
                    extra.insert(
                        "datetime".into(),
                        json!(dt.format("%Y-%m-%d %H:%M:%S").to_string()),
                    );
                }
            }
        } else if let Some(s) = ts.as_str() {
            if !s.trim().is_empty() {
                extra.insert("datetime".into(), json!(s));
            }
        }
    }

    let name = row_str_ci(rm, &["app name", "APPNAME"]).unwrap_or_default();
    let exe = row_str_ci(rm, &["app executable name", "APPEXECUTABLE"]).unwrap_or_default();
    let ver = row_str_ci(rm, &["app bundle version", "APPBUNDLEVERSION"]).unwrap_or_default();
    let message = format!(
        "App Info: app name={name}, app executable name={exe}, bundle id={bid}, app bundle version={ver}, app deleted date={deleted}"
    );
    extra.insert("message".into(), json!(truncate_json_string(&message, 800)));

    merge_app(apps, bid, "powerlogs", Value::Object(extra));
    true
}

/// Read mobipwn Packages' primary inventory table without going through Apollo events.
fn mine_powerlog_app_info_from_archive(
    archive: &SysdiagnoseArchive,
    apps: &mut Map<String, Value>,
) -> usize {
    let Ok(files) = matching_files_patterns(archive, POWERLOG_DB_PATTERNS) else {
        return 0;
    };
    let mut hits = 0usize;
    for (path, bytes) in files {
        if bytes.len() < 16 || &bytes[..15] != b"SQLite format 3" {
            continue;
        }
        let rows = match query_sqlite_select(bytes, POWERLOG_APP_INFO_SQL) {
            Ok(r) => r,
            Err(_) => match query_sqlite_select(bytes, POWERLOG_APP_INFO_SQL_MINIMAL) {
                Ok(r) => r,
                Err(_) => continue,
            },
        };
        for rm in rows {
            if merge_app_info_row(apps, &rm, path) {
                hits += 1;
            }
        }
        if hits > 0 {
            break;
        }
    }
    hits
}

/// Best-effort leading Apple syslog stamp: `Thu Jan  1 12:00:00 2026 …`.
fn mi_line_leading_datetime(line: &str) -> Option<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})",
        )
        .expect("mi syslog ts")
    });
    let caps = re.captures(line)?;
    let mon = caps.get(2)?.as_str();
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hms = caps.get(4)?.as_str();
    let year: i32 = caps.get(5)?.as_str().parse().ok()?;
    let mon_num = match &mon.to_ascii_lowercase()[..] {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let naive = chrono::NaiveDate::from_ymd_opt(year, mon_num, day)?
        .and_time(chrono::NaiveTime::parse_from_str(hms, "%H:%M:%S").ok()?);
    Some(
        chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
    )
}

fn mine_brctl_bundle_ids(
    parsed: &ParsedByParser,
    archive: &SysdiagnoseArchive,
    apps: &mut Map<String, Value>,
) {
    let brctl = get_or_parse(archive, parsed, ParserType::brctl);
    let brctl_text = brctl
        .get("data")
        .map(|d| d.to_string())
        .or_else(|| brctl.get("files").map(|f| f.to_string()))
        .unwrap_or_default();
    if brctl_text.is_empty() || brctl_text == "{}" || brctl_text == "null" {
        return;
    }
    for cap in bundle_id_re().find_iter(&brctl_text) {
        merge_app(
            apps,
            cap.as_str().to_string(),
            "brctl",
            json!({
                "context": brctl_match_context(&brctl_text, &cap),
            }),
        );
    }
}

fn mine_logdata_bundle_ids(
    parsed: &ParsedByParser,
    archive: &SysdiagnoseArchive,
    apps: &mut Map<String, Value>,
) {
    let logdata = get_or_parse(archive, parsed, ParserType::logdata_statistics);
    let Value::Object(paths) = logdata.as_ref() else {
        return;
    };
    for (_p, lines) in paths {
        let Some(arr) = lines.as_array() else {
            continue;
        };
        for line in arr {
            let sub = line
                .get("subsystem")
                .or_else(|| line.get("process"))
                .or_else(|| line.get("data").and_then(|d| d.get("subsystem")))
                .or_else(|| line.get("data").and_then(|d| d.get("process")))
                .and_then(|v| v.as_str());
            let Some(s) = sub.filter(|s| !s.is_empty()) else {
                continue;
            };
            let Some(c) = bundle_id_re().find(s) else {
                continue;
            };
            let mut ex = Map::new();
            if let Some(d) = line.get("data").and_then(|d| d.as_object()) {
                for k in [
                    "subsystem",
                    "category",
                    "process",
                    "pid",
                    "message",
                    "sender",
                    "recipient",
                ] {
                    if let Some(v) = d.get(k) {
                        ex.insert(k.to_string(), v.clone());
                    }
                }
            }
            if let Some(v) = line.get("datetime") {
                ex.insert("datetime".into(), v.clone());
            }
            if let Some(v) = line.get("message") {
                ex.insert("log_message".into(), v.clone());
            }
            if let Some(v) = line.get("subsystem").or_else(|| line.get("process")) {
                ex.insert("top_level_hint".into(), v.clone());
            }
            merge_app(
                apps,
                c.as_str().to_string(),
                "logdata_statistics",
                Value::Object(ex),
            );
        }
    }
}

#[cfg(test)]
mod apps_analyser_tests {
    use super::*;
    use std::collections::HashMap;

    use crate::archive::SysdiagnoseArchive;

    fn minimal_parsed_stub() -> ParsedByParser {
        let mut m = HashMap::new();
        m.insert("powerlogs".to_string(), Arc::new(json!({})));
        m.insert("mobilebackup".to_string(), Arc::new(json!({})));
        m.insert(
            "plists".to_string(),
            Arc::new(json!({ "parser": "plists", "files": {} })),
        );
        m
    }

    #[test]
    fn bundle_id_regex_rejects_numeric_dot_tokens() {
        assert!(super::super::common::bundle_id_re().find("0.0").is_none());
        assert!(super::super::common::bundle_id_re()
            .find("102470.26040317")
            .is_none());
        assert!(super::super::common::bundle_id_re()
            .find("com.apple.mobilesafari")
            .is_some());
    }

    #[test]
    fn canonicalize_rolls_up_staging_and_appex_ids() {
        use super::super::common::canonicalize_app_bundle_id;
        assert_eq!(
            canonicalize_app_bundle_id(
                "B723E939-FEC7-49A2-9D0D-FC199494A818_com.cbouvat.saracroche"
            )
            .as_deref(),
            Some("com.cbouvat.saracroche")
        );
        assert_eq!(
            canonicalize_app_bundle_id("com.cbouvat.saracroche.blocker").as_deref(),
            Some("com.cbouvat.saracroche")
        );
        assert_eq!(
            canonicalize_app_bundle_id(
                "com.apple.appstored:[com.apple.AppStore:com.cbouvat.saracroche]"
            )
            .as_deref(),
            Some("com.cbouvat.saracroche")
        );
        assert_eq!(
            canonicalize_app_bundle_id("com.apple.store.Jolly.MessagesExtension").as_deref(),
            Some("com.apple.store.Jolly")
        );
        assert_eq!(
            canonicalize_app_bundle_id("com.apple.store.Jolly.iUpNotification").as_deref(),
            Some("com.apple.store.Jolly")
        );
        assert_eq!(
            canonicalize_app_bundle_id("com.apple.store.Jolly.OrderStatusNotification").as_deref(),
            Some("com.apple.store.Jolly")
        );
        assert_eq!(
            canonicalize_app_bundle_id("com.apple.store.Jolly.OrderStatusPickupNotification")
                .as_deref(),
            Some("com.apple.store.Jolly")
        );
    }

    #[test]
    fn canonicalize_rejects_plist_url_and_asset_noise() {
        use super::super::common::canonicalize_app_bundle_id;
        assert!(canonicalize_app_bundle_id("portal.manage.microsoft.com").is_none());
        assert!(canonicalize_app_bundle_id("clock_1x.png").is_none());
        assert!(canonicalize_app_bundle_id("config.plist").is_none());
        assert!(canonicalize_app_bundle_id("Discovery.svc").is_none());
        assert!(canonicalize_app_bundle_id("MZInit.woa").is_none());
    }

    #[test]
    fn extract_bundle_id_from_mobileinstallation_message() {
        use super::super::common::extract_app_bundle_id_from_text;
        assert_eq!(
            extract_app_bundle_id_from_text(
                "Staging <MIInstallableBundle ID=com.cbouvat.saracroche; Persona=FEEDEEEE, Version=1, ShortVersion=4.12.0>"
            )
            .as_deref(),
            Some("com.cbouvat.saracroche")
        );
        assert_eq!(
            extract_app_bundle_id_from_text(
                "Data container for com.cbouvat.saracroche.blocker is now at /private/var/…"
            )
            .as_deref(),
            Some("com.cbouvat.saracroche")
        );
        assert_eq!(
            extract_app_bundle_id_from_text(
                r#"Installing parallel placeholder for staged update "B723E939-FEC7-49A2-9D0D-FC199494A818_com.cbouvat.saracroche""#
            )
            .as_deref(),
            Some("com.cbouvat.saracroche")
        );
        assert!(extract_app_bundle_id_from_text(
            "Plist URL logs/parsecd/config.plist resources.iphone_clock_1x: https://cdn.smoot.apple.com/image/clock_1x.png"
        )
        .is_none());
    }

    #[test]
    fn run_apps_merges_appex_hits_into_host_app() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({})));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({
                "logs/MobileInstallation/mobile_installation.log.0":
                    "Data container for com.cbouvat.saracroche.blocker is now at /x\n\
                     Staging <MIInstallableBundle ID=com.cbouvat.saracroche; Version=1>\n\
                     Installing parallel placeholder for staged update \"B723E939-FEC7-49A2-9D0D-FC199494A818_com.cbouvat.saracroche\"\n"
            })));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        assert!(apps.get("com.cbouvat.saracroche").is_some());
        assert!(apps.get("com.cbouvat.saracroche.blocker").is_none());
        assert!(apps
            .keys()
            .all(|k| !k.contains("B723E939") && !k.ends_with(".blocker")));
    }

    #[test]
    fn run_apps_reads_sqlite_map_nesting_for_tcc() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({
                "parser": "accessibility_tcc",
                "format": "jsonl",
                "events": [{
                    "data": {
                        "client": "com.example.tccapp",
                        "service": "kTCCServiceCamera",
                        "source_db": "logs/Accessibility/TCC.db",
                        "apollo_module": "tcc_db"
                    }
                }]
            })));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({})));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        let app = apps
            .get("com.example.tccapp")
            .and_then(|v| v.as_object())
            .expect("tcc app");
        let hits = app["hits"].as_array().expect("hits");
        assert!(!hits.is_empty());
        assert_eq!(hits[0]["source"], "accessibility_tcc");
        assert_eq!(hits[0]["sqlite_table"], "tcc_db");
        assert_eq!(hits[0]["service"], "kTCCServiceCamera");
        assert!(hits[0].get("row").is_some());
        assert_eq!(out["wasm_text_fallback"], false);
    }

    #[test]
    fn run_apps_reads_nested_itunes_rows() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({})));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({
                "parser": "itunesstore",
                "source_path": "logs/itunesstored/downloads.99.sqlitedb",
                "data": {
                    "download": [
                        { "bundle_id": "com.example.itunes" }
                    ]
                }
            })));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({})));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        let app = apps
            .get("com.example.itunes")
            .and_then(|v| v.as_object())
            .expect("itunes app");
        assert_eq!(app["hits"][0]["matched_column"], "bundle_id");
        assert_eq!(app["hits"][0]["sqlite_table"], "download");
        assert!(app["hits"][0].get("row").is_some());
    }

    #[test]
    fn run_apps_merges_powerlogs_app_info() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({})));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("powerlogs".to_string(), Arc::new(json!({
                "parser": "powerlogs",
                "format": "jsonl",
                "events": [{
                    "data": {
                        // Real archives often omit bundle id from the Apollo message string.
                        "message": "App Info: app name=Example, app deleted date=NOT DELETED",
                        "app name": "Example",
                        "app executable name": "Example",
                        "bundle id": "com.example.powerlogs",
                        "app bundle version": "1.2.3",
                        "app build version": "456",
                        "app deleted date": "NOT DELETED",
                        "app type": "User",
                        "source_db": "logs/powerlogs/p.db",
                        "apollo_module": "powerlog_app_info"
                    }
                }, {
                    "data": {
                        "zbundlename": "com.should.ignore.non.appinfo",
                        "source_db": "logs/powerlogs/p.db",
                        "apollo_module": "powerlog_other"
                    }
                }]
            })));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        assert!(apps.get("com.should.ignore.non.appinfo").is_none());
        let app = apps
            .get("com.example.powerlogs")
            .and_then(|v| v.as_object())
            .expect("powerlogs App Info app");
        let h0 = &app["hits"][0];
        assert_eq!(h0["matched_in"], "app_info_message");
        assert_eq!(h0["sqlite_table"], "powerlog_app_info");
        assert_eq!(h0["app name"], "Example");
        assert_eq!(h0["bundle id"], "com.example.powerlogs");
        assert_eq!(out["app_info_hits"], 1);
        assert_eq!(out["wasm_text_fallback"], false);
    }

    #[test]
    fn run_apps_falls_back_to_brctl_when_preferred_empty() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({
            "parser": "accessibility_tcc",
            "format": "jsonl",
            "events": []
        })));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("brctl".to_string(), Arc::new(json!({
                "parser": "brctl",
                "data": "id=\"com.example.frombrctl\" localizedName=\"Demo\""
            })));
        parsed.insert("logdata_statistics".to_string(), Arc::new(json!({})));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        assert_eq!(out["wasm_text_fallback"], true);
        assert!(out["apps"]
            .as_object()
            .unwrap()
            .contains_key("com.example.frombrctl"));
    }

    #[test]
    fn run_apps_reads_app_info_table_from_archive_powerlog() {
        use rusqlite::Connection;

        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS (
                ID INTEGER PRIMARY KEY,
                TIMESTAMP INTEGER,
                APPNAME TEXT,
                APPEXECUTABLE TEXT,
                APPBUNDLEID TEXT,
                APPBUILDVERSION TEXT,
                APPBUNDLEVERSION TEXT,
                APPTYPE INTEGER,
                APPDELETEDDATE INTEGER
            );
            INSERT INTO PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
                (TIMESTAMP, APPNAME, APPEXECUTABLE, APPBUNDLEID, APPBUILDVERSION, APPBUNDLEVERSION, APPTYPE, APPDELETEDDATE)
            VALUES
                (1700000000, 'Saracroche', 'Saracroche', 'com.cbouvat.saracroche', '100', '4.12.0', 4, 0),
                (1700000001, 'Safari', 'MobileSafari', 'com.apple.mobilesafari', '1', '17.0', 3, 0);")
        .unwrap();
        let bytes: Arc<[u8]> = std::fs::read(path.path()).unwrap().into();

        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({ "parser": "accessibility_tcc", "format": "jsonl", "events": [] })));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("powerlogs".to_string(), Arc::new(json!({ "parser": "powerlogs", "format": "jsonl", "events": [] })));

        let mut files = HashMap::new();
        files.insert(
            "logs/powerlogs/powerlog_2024.PLSQL".to_string(),
            bytes,
        );
        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        assert!(apps.contains_key("com.cbouvat.saracroche"));
        assert!(apps.contains_key("com.apple.mobilesafari"));
        assert!(out["app_info_hits"].as_u64().unwrap() >= 2);
        assert!(out["app_info_direct_hits"].as_u64().unwrap() >= 2);
        assert_eq!(out["wasm_text_fallback"], false);
        let hit = &apps["com.cbouvat.saracroche"]["hits"].as_array().unwrap()[0];
        assert_eq!(hit["source"], "powerlogs");
        assert_eq!(hit["app name"], "Saracroche");
        assert_eq!(hit["app bundle version"], "4.12.0");
    }

    #[test]
    fn run_apps_skips_brctl_when_mobileinstallation_has_apps() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({})));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({
                "logs/MobileInstallation/mobile_installation.log.0":
                    "Staging <MIInstallableBundle ID=com.example.keepme; Version=1>\n"
            })));
        parsed.insert("brctl".to_string(), Arc::new(json!({
                "parser": "brctl",
                "data": "id=\"com.noise.frombrctl\" localizedName=\"Noise\""
            })));
        parsed.insert("logdata_statistics".to_string(), Arc::new(json!({})));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        assert!(apps.contains_key("com.example.keepme"));
        assert!(!apps.contains_key("com.noise.frombrctl"));
        assert_eq!(out["wasm_text_fallback"], false);
    }

    #[test]
    fn run_apps_merges_mobilebackup_and_itunes_metadata_plists() {
        let mut parsed = minimal_parsed_stub();
        parsed.insert("accessibility_tcc".to_string(), Arc::new(json!({})));
        parsed.insert("itunesstore".to_string(), Arc::new(json!({})));
        parsed.insert("appinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobileinstallation".to_string(), Arc::new(json!({})));
        parsed.insert("mobilebackup".to_string(), Arc::new(json!({
                "logs/MobileBackup/com.apple.MobileBackup.plist": {
                    "Installed Applications": ["com.backup.listed"],
                    "K": { "softwareVersionBundleId": "com.backup.nested" }
                }
            })));
        parsed.insert("plists".to_string(), Arc::new(json!({
                "parser": "plists",
                "files": {
                    "Containers/Bundle/Application/uuid/iTunesMetadata.plist": {
                        "softwareVersionBundleId": "com.example.itunesmeta"
                    }
                }
            })));

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let out = run(&parsed, &arch);
        let apps = out["apps"].as_object().unwrap();
        assert!(apps.contains_key("com.backup.listed"));
        assert!(apps.contains_key("com.backup.nested"));
        assert!(apps.contains_key("com.example.itunesmeta"));
        let meta = apps["com.example.itunesmeta"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["source"] == "plists_itunes_metadata")
            .expect("plist hit");
        assert!(meta["plist_path"]
            .as_str()
            .unwrap()
            .contains("iTunesMetadata.plist"));
    }
}
