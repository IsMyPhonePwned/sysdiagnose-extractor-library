//! Logic ported from upstream SAF Python parsers ([`EC-DIGIT-CSIRC/sysdiagnose`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose)):
//! SAF-style `Event` dictionaries (`datetime`, `message`, `timestamp_desc`, `module`, `data`) and
//! timeline extraction helpers used by the thin `*_parser.rs` modules.

use std::error::Error;

use globset::Error as GlobError;

use crate::archive::SysdiagnoseArchive;
use crate::glob_match::matching_files_patterns;
use crate::parsers::parser_helpers::MAX_UTF8_FILE;

mod appinstall;
mod auth;
mod avconf;
mod battery;
mod brctl;
mod common;
mod disks;
mod kbdebug;
mod lockdownd;
mod logdata;
mod multiline;
mod plistish;
mod security_sysdiagnose;
mod spindumpnosymbols;
mod swcutil;
mod wifi;
mod wifi_known_networks;
mod wifinetworks;
mod wifiscan;
mod wifisecurity;

pub use appinstall::appinstallation_events_from_tables;
pub use auth::{classify_ios_auth_message, stamp_auth_classification, AuthClassification};
pub use avconf::{decompress_gzip, parse_avconference_gzip};
pub use battery::parse_battery_bdc_csv;
pub use brctl::parse_brctl_folder;
pub use common::{naive_utc, naive_with_offset, saf_event_dict, sysdiagnose_creation, wrap_jsonl};
pub use disks::parse_disks_txt;
pub use kbdebug::parse_kbdebug_log;
pub use lockdownd::extract_lockdownd;
pub use logdata::{parse_logdata_statistics_jsonl, parse_logdata_statistics_txt};
pub use multiline::extract_multiline_log;
pub use plistish::{
    mc_settings_events, mcstate_shared_profile_events, mobilebackup_events, olddsc_events,
    transparency_extract_events,
};
pub use security_sysdiagnose::parse_security_sysdiagnose;
pub use spindumpnosymbols::parse_spindump_nosymbols_text;
pub use swcutil::parse_swcutil_show;
pub use wifi::{f64_from_plist, parse_wifi_timestamp, wifi_network_dicts};
pub use wifi_known_networks::events_from_known_networks_plist;
pub use wifinetworks::events_from_wifinetworks_files;
pub use wifiscan::parse_wifi_scan;
pub use wifisecurity::parse_wifi_security;

/// Read all archive paths matching `patterns` into UTF-8 strings (skips entries over [`MAX_UTF8_FILE`]).
pub fn matching_utf8_files(
    archive: &SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Vec<(String, String)>, Box<dyn Error + Send + Sync>> {
    let files = matching_files_patterns(archive, patterns).map_err(|e: GlobError| e.to_string())?;
    let mut v = Vec::new();
    for (p, b) in files {
        if b.len() > MAX_UTF8_FILE {
            continue;
        }
        v.push((p.to_string(), String::from_utf8_lossy(b).into_owned()));
    }
    Ok(v)
}

#[cfg(test)]
mod tests;
