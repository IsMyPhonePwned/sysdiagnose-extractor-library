//! Correlate MobileInstallation install/delete events with nearby IPA / sideload-tool
//! activity (TrollStore, TrollDecrypt, AltStore, …).

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::parsers::ParserType;
use crate::util::{looks_like_app_version, parse_mobile_install_versions};

use super::common::{
    extract_app_bundle_id_from_text, get_or_parse, value_looks_like_hard_error, ParsedByParser,
};

const DEFAULT_WINDOW_MINUTES: u64 = 30;
const HITS_CAP: usize = 2_000;
const EVENTS_CAP: usize = 500;

const SOURCE_PARSERS: &[ParserType] = &[
    ParserType::mobileinstallation,
    ParserType::logarchive,
    ParserType::crashlogs,
    ParserType::plists,
    ParserType::ps,
    ParserType::psthread,
    ParserType::shutdownlogs,
    ParserType::powerlogs,
    ParserType::transparency_json,
    ParserType::appinstallation,
];

#[derive(Clone)]
struct NamePattern {
    re: Regex,
    name: String,
}

#[derive(Clone)]
struct Rule {
    id: String,
    kind: String,
    label: String,
    match_re: Regex,
    name_patterns: Vec<NamePattern>,
}

fn default_rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            Rule {
                id: "ipa".into(),
                kind: "ipa".into(),
                label: "IPA".into(),
                match_re: Regex::new(r"(?i)\.ipa\b").expect("ipa"),
                name_patterns: vec![NamePattern {
                    re: Regex::new(r"(?i)([\w.-]+\.ipa)\b").expect("ipa name"),
                    name: "$1".into(),
                }],
            },
            Rule {
                id: "sideload_tool".into(),
                kind: "sideload_tool".into(),
                label: "Sideload tool".into(),
                match_re: Regex::new(
                    r"(?i)troll\s*store|trolldecrypt|com\.fiore\.trolldecrypt|alt\s*store|sideloadly|\bscarlet\b|\besign\b|\bfeather\b",
                )
                .expect("sideload"),
                name_patterns: vec![
                    NamePattern {
                        re: Regex::new(r"(?i)trolldecrypt|com\.fiore\.trolldecrypt")
                            .expect("td"),
                        name: "TrollDecrypt".into(),
                    },
                    NamePattern {
                        re: Regex::new(r"(?i)troll\s*store").expect("ts"),
                        name: "TrollStore".into(),
                    },
                    NamePattern {
                        re: Regex::new(r"(?i)alt\s*store").expect("alt"),
                        name: "AltStore".into(),
                    },
                    NamePattern {
                        re: Regex::new(r"(?i)sideloadly").expect("sl"),
                        name: "Sideloadly".into(),
                    },
                    NamePattern {
                        re: Regex::new(r"(?i)\bscarlet\b").expect("sc"),
                        name: "Scarlet".into(),
                    },
                    NamePattern {
                        re: Regex::new(r"(?i)\besign\b").expect("es"),
                        name: "ESign".into(),
                    },
                    NamePattern {
                        re: Regex::new(r"(?i)\bfeather\b").expect("fe"),
                        name: "Feather".into(),
                    },
                ],
            },
        ]
    })
}

fn apply_name_template(template: &str, caps: &regex::Captures) -> String {
    let mut out = template.to_string();
    for i in 0..caps.len() {
        let needle = format!("${i}");
        if let Some(m) = caps.get(i) {
            out = out.replace(&needle, m.as_str());
        }
    }
    out
}

fn name_from_hay(rule: &Rule, hay: &str) -> Option<String> {
    for p in &rule.name_patterns {
        if let Some(caps) = p.re.captures(hay) {
            let named = apply_name_template(&p.name, &caps).trim().to_string();
            if !named.is_empty() {
                return Some(named);
            }
        }
    }
    None
}

fn delete_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(uninstall(?:ed|ing)?|remov(?:e|ed|ing)|destroy(?:ed|ing)?|delet(?:e|ed|ing)|purged?|wipe[sd]?)\b",
        )
        .expect("delete")
    })
}

fn install_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(staging|miinstallable|installable|install(?:ed|ing)?|created?\s+staging|successfully\s+installed)\b",
        )
        .expect("install")
    })
}

fn classify_mi_kind(message: &str, action: &str) -> Option<&'static str> {
    let hay = format!("{action} {message}");
    if delete_re().is_match(&hay) {
        return Some("deleted");
    }
    if install_re().is_match(&hay) {
        return Some("installed");
    }
    None
}

fn parse_datetime_ms(s: &str) -> i64 {
    if s.is_empty() {
        return 0;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return dt.timestamp_millis();
    }
    // Truncate fractional seconds for chrono NaiveDateTime fallbacks.
    let cleaned = s.replace(' ', "T");
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&format!(
        "{}{}",
        cleaned.trim_end_matches('Z'),
        if cleaned.ends_with('Z') { "Z" } else { "+00:00" }
    )) {
        return dt.timestamp_millis();
    }
    0
}

fn field_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn haystack_from_map(map: &Map<String, Value>) -> String {
    [
        "message",
        "path",
        "file_path",
        "process_name",
        "bundle_id",
        "command",
        "command_line",
    ]
    .iter()
    .filter_map(|k| map.get(*k).and_then(|v| v.as_str()))
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("\n")
}

fn walk_objects(v: &Value, out: &mut Vec<Map<String, Value>>, cap: usize) {
    if out.len() >= cap {
        return;
    }
    match v {
        Value::Object(m) => {
            let looks_event = m.contains_key("message")
                || m.contains_key("datetime")
                || m.contains_key("bundle_id")
                || m.contains_key("path");
            if looks_event {
                // Flatten nested `data` into a working map for haystacks.
                let mut flat = m.clone();
                if let Some(Value::Object(data)) = m.get("data") {
                    for (k, val) in data {
                        flat.entry(k.clone()).or_insert_with(|| val.clone());
                    }
                }
                out.push(flat);
            }
            for child in m.values() {
                walk_objects(child, out, cap);
                if out.len() >= cap {
                    return;
                }
            }
        }
        Value::Array(a) => {
            for child in a {
                walk_objects(child, out, cap);
                if out.len() >= cap {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn app_match_tokens(bundle_id: &str, label: &str) -> Vec<String> {
    let skip: HashSet<&str> = [
        "com", "net", "org", "app", "ios", "apple", "android", "mobile", "the",
    ]
    .into_iter()
    .collect();
    let from_bundle: Vec<String> = bundle_id
        .to_ascii_lowercase()
        .split('.')
        .filter(|p| p.len() >= 3 && !skip.contains(p))
        .map(str::to_string)
        .collect();
    let from_label: Vec<String> = label
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 3 && !skip.contains(t))
        .map(str::to_string)
        .collect();
    let preferred: Vec<String> = from_bundle.iter().rev().take(2).cloned().collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for t in preferred.into_iter().chain(from_label).chain(from_bundle) {
        if seen.insert(t.clone()) {
            out.push(t);
        }
    }
    out
}

fn hay_mentions_app(hay: &str, bundle_id: &str, tokens: &[String]) -> bool {
    let h = hay.to_ascii_lowercase();
    if !bundle_id.is_empty() && h.contains(&bundle_id.to_ascii_lowercase()) {
        return true;
    }
    tokens
        .iter()
        .any(|t| t.len() >= 3 && h.contains(&t.to_ascii_lowercase()))
}

fn bundle_label(bundle_id: &str) -> String {
    if bundle_id.is_empty() {
        return "Unknown app".into();
    }
    let parts: Vec<_> = bundle_id.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        bundle_id.to_string()
    }
}

#[derive(Clone)]
struct MiEvent {
    kind: String,
    bundle_id: String,
    label: String,
    version: String,
    timestamp_ms: i64,
    datetime: String,
    message: String,
}

#[derive(Clone)]
struct ClassifiedHit {
    kind: String,
    rule_id: String,
    label: String,
    detail: String,
    timestamp_ms: i64,
    datetime: String,
    parser: String,
    hay: String,
}

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let rules = default_rules();
    let window_ms = (DEFAULT_WINDOW_MINUTES as i64) * 60_000;

    let mut mi_events: Vec<MiEvent> = Vec::new();
    let mut hits: Vec<ClassifiedHit> = Vec::new();

    for &pt in SOURCE_PARSERS {
        let raw = get_or_parse(archive, parsed, pt);
        if value_looks_like_hard_error(&raw) {
            continue;
        }
        let parser_id = pt.as_str();
        let mut objs = Vec::new();
        walk_objects(&raw, &mut objs, HITS_CAP);
        for map in objs {
            let message = field_str(&map, "message");
            let datetime = field_str(&map, "datetime");
            let ts = parse_datetime_ms(&datetime);
            let hay = haystack_from_map(&map);
            if hay.trim().is_empty() {
                continue;
            }

            if parser_id == "mobileinstallation" {
                let action = field_str(&map, "event_type");
                if let Some(kind) = classify_mi_kind(&message, &action) {
                    let bundle = field_str(&map, "bundle_id");
                    let bundle = if bundle.is_empty() {
                        extract_app_bundle_id_from_text(&message).unwrap_or_default()
                    } else {
                        bundle
                    };
                    if !bundle.is_empty() {
                        let vers = parse_mobile_install_versions(&message);
                        let short = map
                            .get("short_version")
                            .and_then(|v| v.as_str())
                            .filter(|s| looks_like_app_version(s))
                            .map(str::to_string)
                            .or(vers.short_version)
                            .or(vers.version)
                            .unwrap_or_default();
                        mi_events.push(MiEvent {
                            kind: kind.into(),
                            bundle_id: bundle.clone(),
                            label: bundle_label(&bundle),
                            version: short,
                            timestamp_ms: ts,
                            datetime: datetime.clone(),
                            message: message.clone(),
                        });
                    }
                }
            }

            for rule in rules.iter() {
                if !rule.match_re.is_match(&hay) {
                    continue;
                }
                let name = name_from_hay(rule, &hay);
                let label = name.unwrap_or_else(|| rule.label.clone());
                let detail = if !message.is_empty() {
                    message.clone()
                } else {
                    field_str(&map, "path")
                };
                hits.push(ClassifiedHit {
                    kind: rule.kind.clone(),
                    rule_id: rule.id.clone(),
                    label,
                    detail,
                    timestamp_ms: ts,
                    datetime: datetime.clone(),
                    parser: parser_id.to_string(),
                    hay: hay.clone(),
                });
            }
        }
    }

    mi_events.truncate(EVENTS_CAP);

    let mut enriched = Vec::new();
    for ev in &mi_events {
        let tokens = app_match_tokens(&ev.bundle_id, &ev.label);
        let nearby: Vec<&ClassifiedHit> = hits
            .iter()
            .filter(|h| {
                ev.timestamp_ms > 0
                    && h.timestamp_ms > 0
                    && (h.timestamp_ms - ev.timestamp_ms).abs() <= window_ms
            })
            .collect();

        let direct: Vec<&ClassifiedHit> = nearby
            .iter()
            .copied()
            .filter(|h| hay_mentions_app(&h.hay, &ev.bundle_id, &tokens))
            .collect();
        let has_direct_ipa = direct.iter().any(|h| h.kind == "ipa");
        let reinstall_after_delete = ev.kind == "installed"
            && mi_events.iter().any(|other| {
                other.kind == "deleted"
                    && other.bundle_id == ev.bundle_id
                    && other.timestamp_ms > 0
                    && ev.timestamp_ms >= other.timestamp_ms
                    && ev.timestamp_ms - other.timestamp_ms <= window_ms
            });

        let tools_via_context: Vec<&ClassifiedHit> = if has_direct_ipa || reinstall_after_delete {
            nearby
                .iter()
                .copied()
                .filter(|h| {
                    h.kind == "sideload_tool"
                        && !direct.iter().any(|d| {
                            d.rule_id == h.rule_id
                                && d.label.eq_ignore_ascii_case(&h.label)
                                && d.timestamp_ms == h.timestamp_ms
                        })
                })
                .collect()
        } else {
            Vec::new()
        };

        // Dump-then-uninstall: tool logs rarely name the target app.
        let tools_near_delete: Vec<&ClassifiedHit> = if ev.kind == "deleted" {
            nearby
                .iter()
                .copied()
                .filter(|h| {
                    h.kind == "sideload_tool"
                        && !direct.iter().any(|d| {
                            d.rule_id == h.rule_id
                                && d.label.eq_ignore_ascii_case(&h.label)
                                && d.timestamp_ms == h.timestamp_ms
                        })
                })
                .collect()
        } else {
            Vec::new()
        };

        let later_delete = if ev.kind == "installed" && ev.timestamp_ms > 0 {
            mi_events
                .iter()
                .filter(|other| {
                    other.kind == "deleted"
                        && other.bundle_id == ev.bundle_id
                        && other.timestamp_ms > ev.timestamp_ms
                })
                .min_by_key(|o| o.timestamp_ms)
        } else {
            None
        };

        let tools_between_install_and_delete: Vec<&ClassifiedHit> =
            if let Some(del) = later_delete {
                hits
                    .iter()
                    .filter(|h| {
                        h.kind == "sideload_tool"
                            && h.timestamp_ms > 0
                            && h.timestamp_ms >= ev.timestamp_ms
                            && h.timestamp_ms <= del.timestamp_ms + window_ms
                            && !direct.iter().any(|d| {
                                d.rule_id == h.rule_id
                                    && d.label.eq_ignore_ascii_case(&h.label)
                                    && d.timestamp_ms == h.timestamp_ms
                            })
                    })
                    .collect()
            } else {
                Vec::new()
            };

        let mut seen = HashSet::new();
        let mut enrichments = Vec::new();
        for h in direct
            .into_iter()
            .chain(tools_via_context)
            .chain(tools_near_delete)
            .chain(tools_between_install_and_delete)
        {
            let dedupe = format!("{}|{}", h.kind, h.label.to_ascii_lowercase());
            if !seen.insert(dedupe) {
                continue;
            }
            enrichments.push(json!({
                "kind": h.kind,
                "rule_id": h.rule_id,
                "label": h.label,
                "detail": h.detail,
                "datetime": h.datetime,
                "timestamp_ms": h.timestamp_ms,
                "parser": h.parser,
            }));
        }
        enrichments.sort_by(|a, b| {
            let ak = a["kind"].as_str().unwrap_or("");
            let bk = b["kind"].as_str().unwrap_or("");
            ak.cmp(bk).then_with(|| {
                a["label"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["label"].as_str().unwrap_or(""))
            })
        });

        enriched.push(json!({
            "kind": ev.kind,
            "bundle_id": ev.bundle_id,
            "label": ev.label,
            "version": ev.version,
            "datetime": ev.datetime,
            "timestamp_ms": ev.timestamp_ms,
            "message": ev.message,
            "enrichments": enrichments,
        }));
    }

    json!({
        "analyser": "install_enrichment",
        "window_minutes": DEFAULT_WINDOW_MINUTES,
        "event_count": enriched.len(),
        "events": enriched,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{looks_like_app_version, parse_mobile_install_versions};

    #[test]
    fn version_helpers_reject_prose() {
        let prose = parse_mobile_install_versions("version does not match");
        assert!(prose.short_version.is_none());
        assert!(!looks_like_app_version("does"));
    }

    #[test]
    fn correlate_reinstall_attaches_trolldecrypt() {
        let mut parsed: ParsedByParser = std::collections::HashMap::new();
        parsed.insert(
            "mobileinstallation".into(),
            json!({
                "parser": "mobileinstallation",
                "format": "jsonl",
                "events": [
                    {
                        "datetime": "2026-01-01T12:00:00.000000Z",
                        "message": "Destroying <MIInstallableBundle ID=org.whispersystems.signal>",
                        "data": { "event_type": "Destroying", "bundle_id": "org.whispersystems.signal" }
                    },
                    {
                        "datetime": "2026-01-01T12:10:00.000000Z",
                        "message": "Staging <MIInstallableBundle ID=org.whispersystems.signal; Version=1, ShortVersion=7.12.0>",
                        "data": {
                            "event_type": "Staging",
                            "bundle_id": "org.whispersystems.signal",
                            "short_version": "7.12.0"
                        }
                    }
                ]
            }),
        );
        parsed.insert(
            "logarchive".into(),
            json!({
                "parser": "logarchive",
                "events": [{
                    "datetime": "2026-01-01T12:05:00.000000Z",
                    "message": "TrollDecrypt finished dumping org.whispersystems.signal",
                    "process_name": "TrollDecrypt"
                }]
            }),
        );
        let arch = crate::SysdiagnoseArchive::from_files_for_test(Default::default());
        let out = run(&parsed, &arch);
        assert_eq!(out["analyser"], "install_enrichment");
        let events = out["events"].as_array().unwrap();
        let install = events
            .iter()
            .find(|e| e["kind"] == "installed")
            .expect("install");
        assert_eq!(install["version"], "7.12.0");
        let labels: Vec<_> = install["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["label"].as_str())
            .collect();
        assert!(labels.iter().any(|l| *l == "TrollDecrypt"), "{labels:?}");
    }

    #[test]
    fn dump_then_uninstall_attaches_tool_without_app_token() {
        let mut parsed: ParsedByParser = std::collections::HashMap::new();
        parsed.insert(
            "mobileinstallation".into(),
            json!({
                "parser": "mobileinstallation",
                "format": "jsonl",
                "events": [{
                    "datetime": "2025-04-07T14:40:47.000000Z",
                    "message": "Uninstalling identifier org.whispersystems.signal",
                    "data": {
                        "event_type": "Uninstalling",
                        "bundle_id": "org.whispersystems.signal"
                    }
                }]
            }),
        );
        parsed.insert(
            "powerlogs".into(),
            json!({
                "parser": "powerlogs",
                "events": [{
                    "datetime": "2025-04-07T14:22:00.000000Z",
                    "message": "App Usage: approle=1, display=0",
                    "bundle_id": "com.fiore.trolldecrypt"
                }]
            }),
        );
        let arch = crate::SysdiagnoseArchive::from_files_for_test(Default::default());
        let out = run(&parsed, &arch);
        let deleted = out["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "deleted")
            .expect("deleted");
        let labels: Vec<_> = deleted["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["label"].as_str())
            .collect();
        assert!(labels.iter().any(|l| *l == "TrollDecrypt"), "{labels:?}");
    }

    #[test]
    fn lone_install_without_tokens_does_not_attach_nearby_tool() {
        let mut parsed: ParsedByParser = std::collections::HashMap::new();
        parsed.insert(
            "mobileinstallation".into(),
            json!({
                "parser": "mobileinstallation",
                "format": "jsonl",
                "events": [{
                    "datetime": "2025-04-07T13:13:50.000000Z",
                    "message": "Installing org.whispersystems.signal",
                    "data": {
                        "event_type": "Installing",
                        "bundle_id": "org.whispersystems.signal"
                    }
                }]
            }),
        );
        parsed.insert(
            "powerlogs".into(),
            json!({
                "parser": "powerlogs",
                "events": [{
                    "datetime": "2025-04-07T13:20:00.000000Z",
                    "message": "App Usage: approle=1",
                    "bundle_id": "com.fiore.trolldecrypt"
                }]
            }),
        );
        let arch = crate::SysdiagnoseArchive::from_files_for_test(Default::default());
        let out = run(&parsed, &arch);
        let install = out["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "installed")
            .expect("installed");
        let enrichments = install["enrichments"].as_array().unwrap();
        assert!(
            enrichments.is_empty(),
            "expected no attach without delete/tokens: {enrichments:?}"
        );
    }
}
