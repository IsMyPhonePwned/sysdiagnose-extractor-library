//! One smoke test per parser and analyser variant on a minimal in-memory archive.
//! Keep the macro lists in sync with `parsers/parser_type.rs` and `analysers/mod.rs`.
//! Deeper analyser behaviour tests live in `analysers::tests`.

use crate::analysers::{analyser_for, AnalyserType};
use crate::parser_for;
use crate::ParserType;
use crate::SysdiagnoseArchive;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use strum::IntoEnumIterator;

fn minimal_archive() -> SysdiagnoseArchive {
    let mut m = HashMap::new();
    m.insert("dummy.txt".to_string(), Arc::from(&b"x"[..]));
    SysdiagnoseArchive::from_files_for_test(m)
}

fn assert_parser_ok(pt: ParserType) {
    let arch = minimal_archive();
    let res = parser_for(pt).parse(&arch);
    assert!(
        res.is_ok(),
        "parser {:?} ({}): {:?}",
        pt,
        pt.as_str(),
        res.err()
    );
}

fn assert_analyser_ok(at: AnalyserType) {
    let arch = minimal_archive();
    let parsed = HashMap::new();
    let v: Result<Value, _> = analyser_for(at).analyse(&arch, &parsed);
    let v = v.expect("analyser");
    assert_eq!(v["analyser"], at.as_str());
}

macro_rules! parser_smoke {
    ($($name:ident: $variant:path);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                assert_parser_ok($variant);
            }
        )*
    };
}

parser_smoke! {
    parser_accessibility_tcc: ParserType::accessibility_tcc;
    parser_apollo_all: ParserType::apollo_all;
    parser_appinstallation: ParserType::appinstallation;
    parser_avconference_callsettings: ParserType::avconference_callsettings;
    parser_battery_bdc: ParserType::battery_bdc;
    parser_brctl: ParserType::brctl;
    parser_containermanager: ParserType::containermanager;
    parser_crashlogs: ParserType::crashlogs;
    parser_disks: ParserType::disks;
    parser_ioacpiplane: ParserType::ioacpiplane;
    parser_iodevicetree: ParserType::iodevicetree;
    parser_iofirewire: ParserType::iofirewire;
    parser_iopower: ParserType::iopower;
    parser_ioservice: ParserType::ioservice;
    parser_iousb: ParserType::iousb;
    parser_interactionc: ParserType::interactionc;
    parser_itunesstore: ParserType::itunesstore;
    parser_kbdebug: ParserType::kbdebug;
    parser_knowledgec: ParserType::knowledgec;
    parser_lockdownd: ParserType::lockdownd;
    parser_logarchive: ParserType::logarchive;
    parser_logdata_statistics: ParserType::logdata_statistics;
    parser_logdata_statistics_txt: ParserType::logdata_statistics_txt;
    parser_mcsettingsevents: ParserType::mcsettingsevents;
    parser_mcstate_shared_profile: ParserType::mcstate_shared_profile;
    parser_mobileactivation: ParserType::mobileactivation;
    parser_mobilebackup: ParserType::mobilebackup;
    parser_mobileinstallation: ParserType::mobileinstallation;
    parser_networkextension: ParserType::networkextension;
    parser_networkextensioncache: ParserType::networkextensioncache;
    parser_netusage: ParserType::netusage;
    parser_olddsc: ParserType::olddsc;
    parser_plists: ParserType::plists;
    parser_powerlogs: ParserType::powerlogs;
    parser_ps: ParserType::ps;
    parser_psthread: ParserType::psthread;
    parser_quarantine_events: ParserType::quarantine_events;
    parser_remotectl_dumpstate: ParserType::remotectl_dumpstate;
    parser_safari_history: ParserType::safari_history;
    parser_security_sysdiagnose: ParserType::security_sysdiagnose;
    parser_screentime: ParserType::screentime;
    parser_shutdownlogs: ParserType::shutdownlogs;
    parser_spindumpnosymbols: ParserType::spindumpnosymbols;
    parser_swcutil: ParserType::swcutil;
    parser_sys: ParserType::sys;
    parser_taskinfo: ParserType::taskinfo;
    parser_transparency: ParserType::transparency;
    parser_transparency_json: ParserType::transparency_json;
    parser_uuid2path: ParserType::uuid2path;
    parser_wifi_known_networks: ParserType::wifi_known_networks;
    parser_wifinetworks: ParserType::wifinetworks;
    parser_wifiscan: ParserType::wifiscan;
    parser_wifisecurity: ParserType::wifisecurity;
}

macro_rules! analyser_smoke {
    ($($name:ident: $variant:path);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                assert_analyser_ok($variant);
            }
        )*
    };
}

analyser_smoke! {
    analyser_apps: AnalyserType::apps;
    analyser_coverage: AnalyserType::coverage;
    analyser_file_stats: AnalyserType::file_stats;
    analyser_install_enrichment: AnalyserType::install_enrichment;
    analyser_mcstateshared: AnalyserType::mcstateshared;
    analyser_network_iocs: AnalyserType::network_iocs;
    analyser_permissions: AnalyserType::permissions;
    analyser_plist: AnalyserType::plist;
    analyser_ps_everywhere: AnalyserType::ps_everywhere;
    analyser_ps_matrix: AnalyserType::ps_matrix;
    analyser_summary: AnalyserType::summary;
    analyser_timesketch: AnalyserType::timesketch;
    analyser_wifi_geolocation: AnalyserType::wifi_geolocation;
    analyser_wifi_geolocation_kml: AnalyserType::wifi_geolocation_kml;
}

#[test]
fn parser_type_enum_iter_matches_expected_count() {
    assert_eq!(ParserType::iter().count(), 53);
}

#[test]
fn analyser_type_enum_iter_matches_expected_count() {
    assert_eq!(AnalyserType::iter().count(), 14);
}
