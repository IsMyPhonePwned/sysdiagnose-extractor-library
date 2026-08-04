//! Classify iOS lock-screen / passcode / biometric authentication lines
//! (SpringBoard unified logs, MobileLockdown passcode prompts, LocalAuthentication).

use serde_json::{json, Map, Value};

/// Structured outcome for an authentication-related log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthClassification {
    pub success: bool,
    /// `passcode`, `biometric`, or generic `unlock`.
    pub auth_type: &'static str,
    pub timestamp_desc: &'static str,
}

/// Detect lock-screen authentication success/failure from a log message.
///
/// Primary sources (iOS unified logs / lockdownd):
/// - `Processed authentication request (success=YES|NO)` (modern SpringBoard)
/// - `Unlock attempt succeeded: yes|no` (older SpringBoard)
/// - `identity match failed` / `bio unlocked` (biometric)
/// - `Passcode authentication succeeded|failed` (lockdownd USB trust / pairing)
/// - LocalAuthentication biometry lockout (`Code=-8`, "Biometry is locked out")
///
/// Ignores boot noise such as "Biometry is not available before first unlock".
pub fn classify_ios_auth_message(message: &str) -> Option<AuthClassification> {
    let lower = message.to_ascii_lowercase();

    // Boot / first-unlock noise — not a real auth attempt outcome.
    if lower.contains("before first unlock") {
        return None;
    }
    // Companion / Watch pairing stubs ("Échec d'authentification") are not lock-screen PIN.
    if lower.contains("companions not supported") || lower.contains("code=-1000") {
        return None;
    }

    // Failures (check before generic "succeeded" / "unlocked" substrings).
    if lower.contains("processed authentication request (success=no)")
        || lower.contains("processed authentication request (success = no)")
    {
        return Some(AuthClassification {
            success: false,
            auth_type: auth_type_from_processed_request(&lower),
            timestamp_desc: "Authentication Failed",
        });
    }
    if lower.contains("unlock attempt succeeded: no")
        || lower.contains("unlock attempt succeeded:no")
    {
        return Some(AuthClassification {
            success: false,
            auth_type: "passcode",
            timestamp_desc: "Authentication Failed",
        });
    }
    if lower.contains("identity match failed") {
        return Some(AuthClassification {
            success: false,
            auth_type: "biometric",
            timestamp_desc: "Authentication Failed",
        });
    }
    // Face ID / Touch ID match failure (fires just before passcode fallback).
    if lower.contains("processmatchfailreason")
        || lower.contains("process match fail reason")
        || lower.contains("bkmatchoperation::processmatchfailreason")
    {
        return Some(AuthClassification {
            success: false,
            auth_type: "biometric",
            timestamp_desc: "Authentication Failed",
        });
    }
    if lower.contains("passcode authentication failed") {
        return Some(AuthClassification {
            success: false,
            auth_type: "passcode",
            timestamp_desc: "Authentication Failed",
        });
    }
    // Biometric lockout after failed Face ID / Touch ID attempts (forces passcode UI).
    if lower.contains("biometry is locked")
        || lower.contains("needs passcode bio lockout")
        || (lower.contains("passcode lockout") && lower.contains("code=-8"))
        || (lower.contains("code=-8") && lower.contains("biom") && lower.contains("locked out"))
        || lower.contains("device authentication is now locked out")
        || lower.contains("device authentication is locked out")
    {
        return Some(AuthClassification {
            success: false,
            auth_type: "biometric",
            timestamp_desc: "Authentication Failed",
        });
    }

    // Successes.
    if lower.contains("processed authentication request (success=yes)")
        || lower.contains("processed authentication request (success = yes)")
    {
        return Some(AuthClassification {
            success: true,
            auth_type: auth_type_from_processed_request(&lower),
            timestamp_desc: "Authentication Succeeded",
        });
    }
    if lower.contains("unlock attempt succeeded: yes")
        || lower.contains("unlock attempt succeeded:yes")
    {
        return Some(AuthClassification {
            success: true,
            auth_type: "unlock",
            timestamp_desc: "Authentication Succeeded",
        });
    }
    if lower.contains("passcode authentication succeeded") {
        return Some(AuthClassification {
            success: true,
            auth_type: "passcode",
            timestamp_desc: "Authentication Succeeded",
        });
    }
    if lower.contains("bio unlocked")
        || lower.contains("received biometric event: bio unlocked")
    {
        return Some(AuthClassification {
            success: true,
            auth_type: "biometric",
            timestamp_desc: "Authentication Succeeded",
        });
    }

    None
}

fn auth_type_from_processed_request(lower: &str) -> &'static str {
    if lower.contains("haspasscode: yes") || lower.contains("haspasscode:yes") {
        "passcode"
    } else {
        "unlock"
    }
}

/// Merge classification into a SAF `data` object (and optional top-level map).
pub fn stamp_auth_classification(data: &mut Map<String, Value>, c: AuthClassification) {
    data.insert("auth_success".into(), json!(c.success));
    data.insert("success".into(), json!(c.success));
    data.insert("auth_type".into(), json!(c.auth_type));
    data.insert("event_type".into(), json!("authentication_event"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_processed_auth_failure() {
        let c = classify_ios_auth_message(
            "Processed authentication request (success=NO): <SBFAuthenticationRequest: …; hasPasscode: YES>",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_processed_auth_success() {
        let c = classify_ios_auth_message(
            "Processed authentication request (success=YES): <SBFAuthenticationRequest: 0x1; type: 1; hasPasscode: YES>",
        )
        .unwrap();
        assert!(c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_unlock_attempt_failure() {
        let c = classify_ios_auth_message("Unlock attempt succeeded: no").unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_unlock_attempt_success() {
        let c = classify_ios_auth_message("Unlock attempt succeeded: yes").unwrap();
        assert!(c.success);
    }

    #[test]
    fn classifies_biometric_match_failed() {
        let c = classify_ios_auth_message(
            "Base unlock behavior received biometric event: identity match failed",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn classifies_bk_match_fail_reason() {
        let c = classify_ios_auth_message(
            "BKMatchOperation::processMatchFailReason: 1 => delegate:A000007D2CC55E0(<private>)",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn classifies_passcode_bio_lockout_status() {
        let c = classify_ios_auth_message(
            "Passcode view status: Face ID or Mesa needs passcode bio lockout",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn classifies_lockdownd_passcode_success() {
        let c = classify_ios_auth_message("Passcode authentication succeeded.").unwrap();
        assert!(c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_biometry_lockout() {
        let c = classify_ios_auth_message(
            "User 501 is locked out: Error Domain=com.apple.LocalAuthentication Code=-8 \"Biometry is locked out.\" UserInfo={Subcode=3}",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn ignores_before_first_unlock_noise() {
        assert!(classify_ios_auth_message(
            "User 501 is locked out: Error Domain=com.apple.LocalAuthentication Code=-8 \"Biometry is not available before first unlock.\""
        )
        .is_none());
    }

    #[test]
    fn ignores_companion_auth_stubs() {
        assert!(classify_ios_auth_message(
            "companionForUser:501 type:4 -> Error Domain=com.apple.LocalAuthentication Code=-1000 \"companions not supported\" UserInfo={NSLocalizedDescription=Échec d’authentification.}"
        )
        .is_none());
    }

    #[test]
    fn ignores_unrelated() {
        assert!(classify_ios_auth_message("Registered DNS (pairing)").is_none());
    }
}
