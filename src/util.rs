use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

/// True for values that look like app versions (must contain a digit).
/// Rejects prose tokens scraped from lines like "version does not…".
pub fn looks_like_app_version(value: &str) -> bool {
    let v = value
        .trim()
        .trim_end_matches(|c: char| matches!(c, ',' | ';' | ')' | '>'))
        .trim();
    if v.is_empty() || v.len() > 64 {
        return false;
    }
    if !v.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    if v.chars().any(|c| c.is_whitespace() || c == '/' || c == '\\' || c == ',') {
        return false;
    }
    true
}

fn normalize_version_capture(raw: &str) -> Option<String> {
    let v = raw
        .trim()
        .trim_end_matches(|c: char| matches!(c, ',' | ';' | ')' | '>'))
        .trim();
    if looks_like_app_version(v) {
        Some(v.to_string())
    } else {
        None
    }
}

/// Structured versions scraped from MobileInstallation log messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MobileInstallVersions {
    /// Marketing / short version (`ShortVersion` / `CFBundleShortVersionString`).
    pub short_version: Option<String>,
    /// Build / CFBundleVersion (`Version=` / `CFBundleVersion`).
    pub version: Option<String>,
}

/// Parse `ShortVersion=` / `Version=` (and CFBundle* forms) from an MI log line.
///
/// Requires `=` or `:` before the value and [`looks_like_app_version`] on the capture
/// so prose like “version does not…” is never treated as a version.
pub fn parse_mobile_install_versions(message: &str) -> MobileInstallVersions {
    fn pick(message: &str, re: &Regex) -> Option<String> {
        let raw = re
            .captures(message)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("");
        normalize_version_capture(raw)
    }

    static SHORT_EQ: OnceLock<Regex> = OnceLock::new();
    static SHORT_CF: OnceLock<Regex> = OnceLock::new();
    static VER_EQ: OnceLock<Regex> = OnceLock::new();
    static VER_CF: OnceLock<Regex> = OnceLock::new();

    let short_eq = SHORT_EQ.get_or_init(|| {
        Regex::new(r"(?i)ShortVersion\s*=\s*([^;>\s,]+)").expect("ShortVersion")
    });
    let short_cf = SHORT_CF.get_or_init(|| {
        Regex::new(r"(?i)CFBundleShortVersionString\s*[=:]\s*([^\s;,>]+)")
            .expect("CFBundleShortVersionString")
    });
    let ver_eq = VER_EQ.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[;\s,])Version\s*=\s*([^;>\s,]+)").expect("Version=")
    });
    let ver_cf = VER_CF.get_or_init(|| {
        Regex::new(r"(?i)CFBundleVersion\s*[=:]\s*([^\s;,>]+)").expect("CFBundleVersion")
    });

    MobileInstallVersions {
        short_version: pick(message, short_eq).or_else(|| pick(message, short_cf)),
        version: pick(message, ver_eq).or_else(|| pick(message, ver_cf)),
    }
}

/// Stamp `short_version` / `version` / CFBundle* fields onto a SAF-style MI event
/// (`message` + optional `data` object). Idempotent when fields already look valid.
pub fn enrich_mobile_installation_event(ev: &mut Value) {
    let message = ev
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if message.is_empty() {
        return;
    }
    let parsed = parse_mobile_install_versions(&message);

    let Some(data) = ev.get_mut("data").and_then(|d| d.as_object_mut()) else {
        // Flat timeline rows (no nested `data`) — stamp on the root.
        if let Some(obj) = ev.as_object_mut() {
            stamp_version_fields(obj, &parsed);
        }
        return;
    };
    stamp_version_fields(data, &parsed);
}

fn stamp_version_fields(map: &mut Map<String, Value>, parsed: &MobileInstallVersions) {
    let existing_short = map
        .get("short_version")
        .or_else(|| map.get("CFBundleShortVersionString"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let short = parsed
        .short_version
        .clone()
        .or_else(|| existing_short.filter(|s| looks_like_app_version(s)));

    let existing_ver = map
        .get("version")
        .or_else(|| map.get("CFBundleVersion"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let version = parsed
        .version
        .clone()
        .or_else(|| existing_ver.filter(|s| looks_like_app_version(s)));

    // Clear bad prior scrapes (e.g. "does").
    for key in ["short_version", "CFBundleShortVersionString", "version", "CFBundleVersion"] {
        if let Some(Value::String(s)) = map.get(key) {
            if !looks_like_app_version(s) {
                map.remove(key);
            }
        }
    }

    if let Some(sv) = short {
        map.insert("short_version".into(), json!(sv.clone()));
        map.insert("CFBundleShortVersionString".into(), json!(sv));
    }
    if let Some(v) = version {
        map.insert("version".into(), json!(v.clone()));
        map.insert("CFBundleVersion".into(), json!(v));
    }
}

/// Matches `snake_case` in SAF `sysdiagnose.utils.misc`: lowercase and replace
/// non-alphanumeric (except `%`) with `_`.
pub fn snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '%' {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Parse a string to JSON value: try int, then float, else string (mirrors SAF ps parsers).
pub fn parse_cell(s: &str) -> serde_json::Value {
    let t = s.trim();
    if let Ok(i) = t.parse::<i64>() {
        return serde_json::Value::Number(i.into());
    }
    if let Ok(f) = t.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return serde_json::Value::Number(n);
        }
    }
    serde_json::Value::String(t.to_string())
}

/// Strip surrounding double quotes from an Apple process / parent name token.
pub fn strip_process_name_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        return t[1..t.len() - 1].to_string();
    }
    t.trim_matches('"').trim().to_string()
}

/// True for Apple `ps` TIME values (`0:00.10`, `7:27.40`, `256:23.45`, `1:02:03`).
pub fn looks_like_cpu_time(s: &str) -> bool {
    use regex::Regex;
    use std::sync::OnceLock;

    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^\d+:\d{2}(?::\d{2})?(?:\.\d+)?$").expect("cpu time")
    });
    re.is_match(s.trim())
}

/// If `command` starts with a glued `ps` TIME token, peel it off.
///
/// Happens when whitespace-split column parsing shifts TIME into COMMAND
/// (empty/missing STARTED, or STARTED containing spaces).
pub fn peel_leading_cpu_time(command: &str) -> Option<(String, String)> {
    let t = command.trim();
    let mut parts = t.splitn(2, char::is_whitespace);
    let first = parts.next()?.trim();
    let rest = parts.next()?.trim();
    if rest.is_empty() || !looks_like_cpu_time(first) {
        return None;
    }
    Some((first.to_string(), rest.to_string()))
}

/// Canonical short process name from a `ps` / `psthread` COMMAND string.
///
/// Examples:
/// - `/sbin/launchd` → `launchd`
/// - `sshd: root@ttys000` → `sshd`
/// - `0:00.10 sshd: root@ttys000` → `sshd` (after peeling TIME)
/// - `(kernel_task)` → `kernel_task`
pub fn process_short_name(command: &str) -> String {
    let (_, cleaned) = match peel_leading_cpu_time(command) {
        Some((_, rest)) => (true, rest),
        None => (false, command.trim().to_string()),
    };
    if cleaned.is_empty() {
        return String::new();
    }
    let token = cleaned.split_whitespace().next().unwrap_or(&cleaned);
    let base = token.rsplit('/').next().unwrap_or(token);
    let base = base.trim_matches(|c| c == '(' || c == ')');
    if let Some((head, _)) = base.split_once(':') {
        if !head.is_empty() {
            return head.to_string();
        }
    }
    base.to_string()
}

/// Split a process COMMAND into `(argv0, args)`.
///
/// - `/path/to/mussel dGNwOi8v…` → (`/path/to/mussel`, `dGNwOi8v…`)
/// - `/usr/bin/foo --bar baz` → (`/usr/bin/foo`, `--bar baz`)
/// - `sshd: root@ttys000` → (`sshd: root@ttys000`, ``) — Apple `name: detail` forms
pub fn split_process_command(command: &str) -> (String, String) {
    let cmd = match peel_leading_cpu_time(command) {
        Some((_, rest)) => rest,
        None => command.trim().to_string(),
    };
    if cmd.is_empty() {
        return (String::new(), String::new());
    }
    let first = cmd.split_whitespace().next().unwrap_or(cmd.as_str());
    // Colon forms (`sshd: root@ttys000`, `login:`) are not argv — keep whole string.
    if first.contains(':') && !first.starts_with('/') {
        return (cmd, String::new());
    }
    if let Some((exe, rest)) = cmd.split_once(char::is_whitespace) {
        let rest = rest.trim();
        if !rest.is_empty() {
            return (exe.to_string(), rest.to_string());
        }
    }
    (cmd, String::new())
}

/// Normalize iOS paths so `/private/var/…` and `/var/…` compare equal.
pub fn normalize_process_path(path: &str) -> String {
    let t = path.trim();
    t.strip_prefix("/private")
        .unwrap_or(t)
        .trim_end_matches('/')
        .to_string()
}

/// Repair TIME/COMMAND shift and stamp canonical `name` / `process` / `process_name`
/// on a tabular `ps` / `psthread` row (keeps full COMMAND for forensics).
pub fn enrich_ps_process_row(obj: &mut serde_json::Map<String, serde_json::Value>) {
    use serde_json::json;

    // STARTED empty → TIME/COMMAND shift left: STARTED looks like TIME, TIME is first cmd token.
    let started = obj
        .get("started")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let time = obj
        .get("time")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let command0 = obj
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if looks_like_cpu_time(&started) && !time.is_empty() && !looks_like_cpu_time(&time) {
        obj.insert("time".to_string(), json!(started));
        let rebuilt = if command0.is_empty() {
            time.clone()
        } else {
            format!("{time} {command0}")
        };
        obj.insert("command".to_string(), json!(rebuilt));
        obj.insert("started".to_string(), json!(""));
    }

    let command_raw = obj
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if command_raw.is_empty() {
        return;
    }

    let mut command = command_raw;
    if let Some((peeled_time, rest)) = peel_leading_cpu_time(&command) {
        let time_ok = obj
            .get("time")
            .and_then(|v| v.as_str())
            .map(looks_like_cpu_time)
            .unwrap_or(false);
        if !time_ok {
            obj.insert("time".to_string(), json!(peeled_time));
        }
        command = rest;
        obj.insert("command".to_string(), json!(command.clone()));
    }

    obj.insert("command_line".to_string(), json!(command.clone()));

    let (exe, args) = split_process_command(&command);
    if !args.is_empty() {
        let cur = obj.get("args").and_then(|v| v.as_str()).unwrap_or("");
        if args.len() >= cur.len() {
            obj.insert("args".to_string(), json!(args));
        }
    }
    if exe.starts_with('/') {
        let path_empty = obj
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.is_empty())
            .unwrap_or(true);
        if path_empty {
            obj.insert("path".to_string(), json!(exe));
        }
    }

    let name = process_short_name(&command);
    if name.is_empty() {
        return;
    }
    obj.insert("name".to_string(), json!(name.clone()));
    obj.insert("process".to_string(), json!(name.clone()));
    obj.insert("process_name".to_string(), json!(name));
}

/// Stamp short name / args / path on a merged ps_everywhere (or similar) row.
pub fn enrich_merged_process_row(obj: &mut serde_json::Map<String, serde_json::Value>) {
    use serde_json::json;

    let command = obj
        .get("command")
        .or_else(|| obj.get("command_line"))
        .or_else(|| obj.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if command.is_empty() {
        return;
    }

    if !obj.contains_key("command_line") {
        obj.insert("command_line".to_string(), json!(command.clone()));
    }

    let (exe, args) = split_process_command(&command);
    if !args.is_empty() {
        let cur = obj.get("args").and_then(|v| v.as_str()).unwrap_or("");
        if args.len() >= cur.len() {
            obj.insert("args".to_string(), json!(args));
        }
    }
    if exe.starts_with('/') {
        let path_empty = obj
            .get("path")
            .or_else(|| obj.get("file_path"))
            .and_then(|v| v.as_str())
            .map(|s| s.is_empty())
            .unwrap_or(true);
        if path_empty {
            obj.insert("path".to_string(), json!(exe));
        }
    }

    let name = process_short_name(&command);
    if !name.is_empty() {
        obj.insert("name".to_string(), json!(name.clone()));
        obj.insert("process".to_string(), json!(name.clone()));
        obj.insert("process_name".to_string(), json!(name));
    }
}

/// Parse Apple taskinfo / spindump process identity lines into `(name, pid)`.
///
/// Examples:
/// - `"sshd" [298] [unique ID: 298]` → (`sshd`, `Some(298)`)
/// - `launchd [1]` → (`launchd`, `Some(1)`)
/// - `"My App" [123]` → (`My App`, `Some(123)`)
pub fn parse_process_identity(raw: &str) -> (String, Option<i64>) {
    use regex::Regex;
    use std::sync::OnceLock;

    let s = raw.trim();
    if s.is_empty() {
        return (String::new(), None);
    }

    static PID_RE: OnceLock<Regex> = OnceLock::new();
    static QUOTED_RE: OnceLock<Regex> = OnceLock::new();
    let pid_re = PID_RE.get_or_init(|| Regex::new(r"\[(\d+)\]").expect("pid"));
    let quoted_re = QUOTED_RE.get_or_init(|| Regex::new(r#""([^"]+)""#).expect("quoted name"));

    let pid = pid_re
        .captures(s)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i64>().ok());

    if let Some(cap) = quoted_re.captures(s) {
        if let Some(name) = cap.get(1).map(|m| m.as_str().trim()).filter(|n| !n.is_empty()) {
            return (name.to_string(), pid);
        }
    }

    let name = strip_process_name_quotes(s.split('[').next().unwrap_or(s).trim());
    (name, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_like_python() {
        assert_eq!(snake_case("%CPU"), "%cpu");
        assert_eq!(snake_case("USER"), "user");
        assert_eq!(snake_case("STARTED"), "started");
    }

    #[test]
    fn parse_process_identity_taskinfo_quoted() {
        let (name, pid) = parse_process_identity(r#""sshd" [298] [unique ID: 298]"#);
        assert_eq!(name, "sshd");
        assert_eq!(pid, Some(298));
    }

    #[test]
    fn parse_process_identity_spindump_unquoted() {
        let (name, pid) = parse_process_identity("launchd [1]");
        assert_eq!(name, "launchd");
        assert_eq!(pid, Some(1));
    }

    #[test]
    fn parse_process_identity_quoted_with_spaces() {
        let (name, pid) = parse_process_identity(r#""SpringBoard" [123]"#);
        assert_eq!(name, "SpringBoard");
        assert_eq!(pid, Some(123));
    }

    #[test]
    fn strip_process_name_quotes_basic() {
        assert_eq!(strip_process_name_quotes(r#""sshd""#), "sshd");
        assert_eq!(strip_process_name_quotes("sshd"), "sshd");
    }

    #[test]
    fn peel_leading_cpu_time_from_command() {
        assert_eq!(
            peel_leading_cpu_time("0:00.10 sshd: root@ttys000"),
            Some(("0:00.10".into(), "sshd: root@ttys000".into()))
        );
        assert_eq!(peel_leading_cpu_time("sshd: root@ttys000"), None);
        assert!(looks_like_cpu_time("7:27.40"));
        assert!(!looks_like_cpu_time("sshd:"));
    }

    #[test]
    fn process_short_name_from_ps_command() {
        assert_eq!(process_short_name("/sbin/launchd"), "launchd");
        assert_eq!(process_short_name("sshd: root@ttys000"), "sshd");
        assert_eq!(process_short_name("0:00.10 sshd: root@ttys000"), "sshd");
        assert_eq!(process_short_name("(kernel_task)"), "kernel_task");
    }

    #[test]
    fn split_process_command_extracts_args() {
        let (exe, args) = split_process_command(
            "/private/var/containers/Bundle/Application/UUID/Signal.app/mussel dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==",
        );
        assert!(exe.ends_with("/Signal.app/mussel"));
        assert_eq!(args, "dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==");
        assert_eq!(
            split_process_command("sshd: root@ttys000"),
            ("sshd: root@ttys000".into(), String::new())
        );
        assert_eq!(
            normalize_process_path("/private/var/containers/foo"),
            "/var/containers/foo"
        );
    }

    #[test]
    fn enrich_ps_process_row_repairs_glued_time() {
        use serde_json::{json, Map};
        let mut obj = Map::new();
        obj.insert("command".into(), json!("0:00.10 sshd: root@ttys000"));
        obj.insert("time".into(), json!("sshd:"));
        enrich_ps_process_row(&mut obj);
        assert_eq!(obj.get("command").and_then(|v| v.as_str()), Some("sshd: root@ttys000"));
        assert_eq!(obj.get("time").and_then(|v| v.as_str()), Some("0:00.10"));
        assert_eq!(obj.get("name").and_then(|v| v.as_str()), Some("sshd"));
        assert_eq!(obj.get("process_name").and_then(|v| v.as_str()), Some("sshd"));
        assert_eq!(obj.get("process").and_then(|v| v.as_str()), Some("sshd"));
    }

    #[test]
    fn enrich_ps_process_row_keeps_args() {
        use serde_json::{json, Map};
        let mut obj = Map::new();
        obj.insert(
            "command".into(),
            json!("/var/containers/Bundle/Application/X/Signal.app/mussel dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg=="),
        );
        enrich_ps_process_row(&mut obj);
        assert_eq!(obj.get("process_name").and_then(|v| v.as_str()), Some("mussel"));
        assert_eq!(
            obj.get("args").and_then(|v| v.as_str()),
            Some("dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==")
        );
        assert_eq!(
            obj.get("path").and_then(|v| v.as_str()),
            Some("/var/containers/Bundle/Application/X/Signal.app/mussel")
        );
    }

    #[test]
    fn parse_mobile_install_versions_requires_equals() {
        let ok = parse_mobile_install_versions(
            "Staging <MIInstallableBundle ID=org.whispersystems.signal; Version=1, ShortVersion=7.12.0>",
        );
        assert_eq!(ok.short_version.as_deref(), Some("7.12.0"));
        assert_eq!(ok.version.as_deref(), Some("1"));

        let prose = parse_mobile_install_versions(
            "Install requested; version does not match existing container metadata",
        );
        assert_eq!(prose.short_version, None);
        assert_eq!(prose.version, None);
        assert!(!looks_like_app_version("does"));
    }

    #[test]
    fn enrich_mobile_installation_event_stamps_data() {
        use serde_json::json;
        let mut ev = json!({
            "message": "Staging <MIInstallableBundle ID=org.whispersystems.signal; Version=42, ShortVersion=7.12.0>",
            "data": { "event_type": "Staging" }
        });
        enrich_mobile_installation_event(&mut ev);
        assert_eq!(ev["data"]["short_version"], "7.12.0");
        assert_eq!(ev["data"]["CFBundleShortVersionString"], "7.12.0");
        assert_eq!(ev["data"]["version"], "42");
        assert_eq!(ev["data"]["CFBundleVersion"], "42");

        let mut bad = json!({
            "message": "version does not match",
            "data": { "short_version": "does", "version": "does" }
        });
        enrich_mobile_installation_event(&mut bad);
        assert!(bad["data"].get("short_version").is_none());
        assert!(bad["data"].get("version").is_none());
    }
}
