//! Device-user / Apple-account identity from transparency + plists.
//!
//! Structured counterpart to the markdown sections in [`super::summary`]:
//! MobileCal `OwnerEmailAddress`, MDM `CloudConfigurationDetails` organization
//! email, `ActivationLockUsername` from mobileactivationd logs, transparency
//! contact URIs, selfVerification account keys, and linked `stateMachine.devices`.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::ParserType;

use super::common::{
    get_or_parse, lockdown_mode_from_effective_settings, owner_emails_from_mobilecal,
    walk_transparency_contact_uris, ParsedByParser,
};

/// Identity plists we always want, independent of the capped `**/*.plist` walk.
const IDENTITY_PLIST_PATTERNS: &[&str] = &[
    "**/CloudConfigurationDetails.plist",
    "**/com.apple.mobilecal.plist",
    "**/mobilecal.plist",
    "**/EffectiveUserSettings.plist",
    "**/PublicEffectiveUserSettings.plist",
];

fn mailto_from_uri(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("im://mailto:")
        .or_else(|| uri.strip_prefix("mailto:"))?;
    let email = rest.trim();
    if email.is_empty() || !email.contains('@') {
        return None;
    }
    Some(email.to_string())
}

fn tel_from_uri(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("im://tel:")
        .or_else(|| uri.strip_prefix("tel:"))?;
    let tel = rest.trim();
    if tel.is_empty() {
        return None;
    }
    Some(tel.to_string())
}

fn parse_plist_bytes(bytes: &[u8]) -> Option<Value> {
    let v = plist::from_reader::<_, plist::Value>(Cursor::new(bytes)).ok()?;
    serde_json::to_value(&v).ok()
}

/// Targeted identity plists from the archive (bypasses the 600-file plists cap).
fn identity_plist_files(archive: &SysdiagnoseArchive) -> Map<String, Value> {
    let mut out = Map::new();
    let Ok(files) = matching_files_patterns(archive, IDENTITY_PLIST_PATTERNS) else {
        return out;
    };
    for (path, bytes) in files {
        // Skip AppleDouble / resource-fork sidecars.
        if path.rsplit('/').next().is_some_and(|n| n.starts_with("._")) {
            continue;
        }
        if let Some(v) = parse_plist_bytes(bytes) {
            out.insert(path.to_string(), v);
        }
    }
    out
}

fn collect_owner_emails_from_map(files: &Map<String, Value>, out: &mut Vec<Value>) {
    let mut seen: BTreeSet<String> = out
        .iter()
        .filter_map(|v| v.get("email").and_then(|e| e.as_str()))
        .map(|e| e.to_ascii_lowercase())
        .collect();
    for (path, val) in files {
        if !path.to_ascii_lowercase().contains("mobilecal") {
            continue;
        }
        for email in owner_emails_from_mobilecal(val) {
            if !seen.insert(email.to_ascii_lowercase()) {
                continue;
            }
            out.push(json!({
                "email": email,
                "source": "mobilecal",
                "path": path,
            }));
        }
    }
}

fn organization_email_from_cloud_config(v: &Value) -> Option<(String, Option<String>)> {
    let email = v
        .get("OrganizationEmail")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.contains('@'))?
        .to_string();
    let org = v
        .get("OrganizationName")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some((email, org))
}

fn collect_organization_emails_from_map(files: &Map<String, Value>, out: &mut Vec<Value>) {
    let mut seen: BTreeSet<String> = out
        .iter()
        .filter_map(|v| v.get("email").and_then(|e| e.as_str()))
        .map(|e| e.to_ascii_lowercase())
        .collect();
    for (path, val) in files {
        if !path.contains("CloudConfigurationDetails") {
            continue;
        }
        let Some((email, org)) = organization_email_from_cloud_config(val) else {
            continue;
        };
        if !seen.insert(email.to_ascii_lowercase()) {
            continue;
        }
        let mut row = Map::new();
        row.insert("email".into(), json!(email));
        row.insert("source".into(), json!("cloud_configuration"));
        row.insert("path".into(), json!(path));
        row.insert("account_type".into(), json!("organization_email"));
        if let Some(org) = org {
            row.insert("organization_name".into(), json!(org));
        }
        if let Some(dept) = val
            .get("OrganizationDepartment")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            row.insert("organization_department".into(), json!(dept));
        }
        out.push(Value::Object(row));
    }
}

fn activation_lock_username_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)ActivationLockUsername\s*=\s*"([^"]+)""#).expect("activation lock re")
    })
}

fn push_activation_lock_username(
    username: &str,
    source: &str,
    path: Option<&str>,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<Value>,
) {
    let email = username.trim();
    if email.is_empty() || !email.contains('@') {
        return;
    }
    if !seen.insert(email.to_ascii_lowercase()) {
        return;
    }
    let mut row = Map::new();
    row.insert("email".into(), json!(email));
    row.insert("username".into(), json!(email));
    row.insert("source".into(), json!(source));
    row.insert("account_type".into(), json!("activation_lock"));
    if let Some(path) = path.filter(|p| !p.is_empty()) {
        row.insert("path".into(), json!(path));
    }
    out.push(Value::Object(row));
}

/// Apple ID / Find My Activation Lock username from `mobileactivationd` logs.
fn collect_activation_lock_usernames(
    archive: &SysdiagnoseArchive,
    parsed: &ParsedByParser,
    out: &mut Vec<Value>,
) {
    let mut seen: BTreeSet<String> = out
        .iter()
        .filter_map(|v| v.get("email").and_then(|e| e.as_str()))
        .map(|e| e.to_ascii_lowercase())
        .collect();
    let re = activation_lock_username_re();

    let ma = get_or_parse(archive, parsed, ParserType::mobileactivation);
    if let Some(events) = ma.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            let Some(message) = ev.get("message").and_then(|m| m.as_str()) else {
                continue;
            };
            for caps in re.captures_iter(message) {
                if let Some(m) = caps.get(1) {
                    push_activation_lock_username(
                        m.as_str(),
                        "mobileactivation",
                        None,
                        &mut seen,
                        out,
                    );
                }
            }
        }
    }

    // Fallback: scan raw logs (covers archives where multiline join missed the dict).
    if let Ok(files) =
        matching_files_patterns(archive, &["logs/MobileActivation/mobileactivationd.log*"])
    {
        for (path, bytes) in files {
            if path.rsplit('/').next().is_some_and(|n| n.starts_with("._")) {
                continue;
            }
            let text = String::from_utf8_lossy(bytes);
            for caps in re.captures_iter(&text) {
                if let Some(m) = caps.get(1) {
                    push_activation_lock_username(
                        m.as_str(),
                        "mobileactivation",
                        Some(path),
                        &mut seen,
                        out,
                    );
                }
            }
        }
    }
}

fn collect_lockdown_from_map(files: &Map<String, Value>) -> Option<bool> {
    for (path, val) in files {
        if path.contains("EffectiveUserSettings") {
            if let Some(b) = lockdown_mode_from_effective_settings(val) {
                return Some(b);
            }
        }
    }
    None
}

fn collect_from_transparency(trans: &Value) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let mut contacts = Vec::new();
    let mut apple_accounts = Vec::new();
    let mut linked_devices = Vec::new();

    if trans.get("error").is_some() {
        return (contacts, apple_accounts, linked_devices);
    }

    let mut uris = BTreeSet::new();
    walk_transparency_contact_uris(trans, &mut uris);
    for uri in uris {
        let kind = if uri.contains("mailto:") {
            "mailto"
        } else if uri.contains("tel:") {
            "tel"
        } else {
            "other"
        };
        let email = mailto_from_uri(&uri);
        let phone = tel_from_uri(&uri);
        let mut row = Map::new();
        row.insert("uri".into(), json!(uri));
        row.insert("kind".into(), json!(kind));
        row.insert("source".into(), json!("transparency"));
        if let Some(email) = email {
            row.insert("email".into(), json!(email));
        }
        if let Some(tel) = phone {
            row.insert("phone".into(), json!(tel));
        }
        contacts.push(Value::Object(row));
    }

    if let Some(server) = trans
        .pointer("/stateMachine/selfVerification/server")
        .and_then(|v| v.as_object())
    {
        for key in server.keys() {
            let id = key.trim();
            if id.is_empty() {
                continue;
            }
            apple_accounts.push(json!({
                "account_id": id,
                "account_type": "apple_transparency",
                "source": "transparency_selfVerification",
            }));
        }
    }

    if let Some(devs) = trans
        .pointer("/stateMachine/devices")
        .and_then(|v| v.as_object())
    {
        for (_k, d) in devs {
            let Some(o) = d.as_object() else { continue };
            let serial = o
                .get("serial")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let model = o
                .get("model")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let os_version = o
                .get("osVersion")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let name = o
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if serial.is_empty() && model.is_empty() && name.is_empty() {
                continue;
            }
            linked_devices.push(json!({
                "serial": serial,
                "model": model,
                "os_version": os_version,
                "name": name,
                "source": "transparency_devices",
            }));
        }
    }

    (contacts, apple_accounts, linked_devices)
}

pub fn run(parsed: &ParsedByParser, archive: &SysdiagnoseArchive) -> Value {
    let identity = identity_plist_files(archive);
    let mut owner_emails = Vec::new();
    collect_owner_emails_from_map(&identity, &mut owner_emails);
    let mut organization_emails = Vec::new();
    collect_organization_emails_from_map(&identity, &mut organization_emails);
    let mut activation_lock_usernames = Vec::new();
    collect_activation_lock_usernames(archive, parsed, &mut activation_lock_usernames);
    let mut lockdown_mode = collect_lockdown_from_map(&identity);

    // Fallback: capped recursive plists (legacy paths / already-parsed ingest).
    let plists = get_or_parse(archive, parsed, ParserType::plists);
    if let Some(files) = plists.get("files").and_then(|f| f.as_object()) {
        collect_owner_emails_from_map(files, &mut owner_emails);
        collect_organization_emails_from_map(files, &mut organization_emails);
        if lockdown_mode.is_none() {
            lockdown_mode = collect_lockdown_from_map(files);
        }
    }

    let trans = get_or_parse(archive, parsed, ParserType::transparency_json);
    let (contacts, apple_accounts, linked_devices) = collect_from_transparency(&trans);

    json!({
        "analyser": "accounts",
        "owner_emails": owner_emails,
        "organization_emails": organization_emails,
        "activation_lock_usernames": activation_lock_usernames,
        "contacts": contacts,
        "apple_accounts": apple_accounts,
        "linked_devices": linked_devices,
        "lockdown_mode": lockdown_mode,
        "counts": {
            "owner_emails": owner_emails.len(),
            "organization_emails": organization_emails.len(),
            "activation_lock_usernames": activation_lock_usernames.len(),
            "contacts": contacts.len(),
            "apple_accounts": apple_accounts.len(),
            "linked_devices": linked_devices.len(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SysdiagnoseArchive;
    use std::collections::HashMap;

    #[test]
    fn extracts_mobilecal_and_transparency_identity() {
        let mut parsed = ParsedByParser::new();
        parsed.insert(
            "plists".into(),
            json!({
                "files": {
                    "logs/Preferences/mobilecal.plist": {
                        "OwnerEmailAddress": ["alice@icloud.com", "work@example.com"]
                    },
                    "logs/EffectiveUserSettings.plist": {
                        "restrictedBool": { "allowLockdownMode": { "value": true } }
                    }
                }
            }),
        );
        parsed.insert(
            "transparency_json".into(),
            json!({
                "stateMachine": {
                    "selfVerification": {
                        "server": {
                            "acct-abc": {},
                            "acct-def": {}
                        }
                    },
                    "devices": {
                        "d1": {
                            "serial": "C02TEST",
                            "model": "MacBookPro18,1",
                            "osVersion": "15.0",
                            "name": "Alice's MacBook"
                        }
                    },
                    "contacts": [
                        "im://mailto:alice@icloud.com",
                        "im://tel:+15551212"
                    ]
                }
            }),
        );

        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let v = run(&parsed, &arch);
        assert_eq!(v["analyser"], "accounts");
        assert_eq!(v["counts"]["owner_emails"], 2);
        assert_eq!(v["lockdown_mode"], true);
        assert_eq!(v["apple_accounts"].as_array().unwrap().len(), 2);
        assert_eq!(v["linked_devices"][0]["serial"], "C02TEST");
        assert_eq!(v["linked_devices"][0]["name"], "Alice's MacBook");
        let contacts = v["contacts"].as_array().unwrap();
        assert!(contacts.iter().any(|c| c["email"] == "alice@icloud.com"));
        assert!(contacts.iter().any(|c| c["phone"] == "+15551212"));
    }

    #[test]
    fn extracts_organization_email_from_cloud_configuration() {
        let mut files = HashMap::new();
        files.insert(
            "logs/MCState/Shared/CloudConfigurationDetails.plist".into(),
            std::sync::Arc::<[u8]>::from(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>OrganizationEmail</key>
  <string>jeremy.renard@edf.fr</string>
  <key>OrganizationName</key>
  <string>EDF SA</string>
  <key>OrganizationDepartment</key>
  <string>EDF SA DSIT ITSUP</string>
</dict>
</plist>"#
                    .as_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let v = run(&ParsedByParser::new(), &arch);
        assert_eq!(v["counts"]["organization_emails"], 1);
        assert_eq!(
            v["organization_emails"][0]["email"],
            "jeremy.renard@edf.fr"
        );
        assert_eq!(v["organization_emails"][0]["organization_name"], "EDF SA");
        assert_eq!(
            v["organization_emails"][0]["account_type"],
            "organization_email"
        );
    }

    #[test]
    fn extracts_activation_lock_username_from_mobileactivation_logs() {
        let mut files = HashMap::new();
        files.insert(
            "logs/MobileActivation/mobileactivationd.log.0".into(),
            std::sync::Arc::<[u8]>::from(
                br#"Tue May 26 08:35:38 2026 [148] <notice> (0x16dc6f000) MA: -[MobileActivationDaemon issueUCRT:withCompletionBlock:]: UCRT reissue requested by akd ({
    ActivationLockPET = "REDACTED";
    ActivationLockUsername = "anthony@42.bzh";
})
"#
                .as_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let v = run(&ParsedByParser::new(), &arch);
        assert_eq!(v["counts"]["activation_lock_usernames"], 1);
        assert_eq!(
            v["activation_lock_usernames"][0]["email"],
            "anthony@42.bzh"
        );
        assert_eq!(
            v["activation_lock_usernames"][0]["account_type"],
            "activation_lock"
        );
    }

    #[test]
    fn empty_inputs_yield_zero_counts() {
        let parsed = ParsedByParser::new();
        let arch = SysdiagnoseArchive::from_files_for_test(HashMap::new());
        let v = run(&parsed, &arch);
        assert_eq!(v["counts"]["owner_emails"], 0);
        assert_eq!(v["counts"]["organization_emails"], 0);
        assert_eq!(v["counts"]["activation_lock_usernames"], 0);
        assert_eq!(v["counts"]["contacts"], 0);
        assert_eq!(v["counts"]["apple_accounts"], 0);
        assert_eq!(v["counts"]["linked_devices"], 0);
        assert!(v["lockdown_mode"].is_null());
    }
}
