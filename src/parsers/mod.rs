use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;

mod apollo;
mod dispatch;
mod ioreg;
mod parse_options;
mod parser_events;
mod parser_helpers;
mod plists_config;
mod parser_type;

pub mod accessibility_tcc_parser;
pub mod apollo_all_parser;
pub mod appinstallation_parser;
pub mod avconference_callsettings_parser;
pub mod battery_bdc_parser;
pub mod brctl_parser;
pub mod containermanager_parser;
pub mod crashlogs_ips;
pub mod crashlogs_parser;
pub mod disks_parser;
pub mod ioacpiplane_parser;
pub mod iodevicetree_parser;
pub mod iofirewire_parser;
pub mod iopower_parser;
pub mod ioservice_parser;
pub mod iousb_parser;
pub mod interactionc_parser;
pub mod itunesstore_parser;
pub mod kbdebug_parser;
pub mod knowledgec_parser;
pub mod lockdownd_parser;
pub mod logarchive_decode;
mod logarchive_parser;
pub mod logdata_statistics_parser;
pub mod logdata_statistics_txt_parser;
pub mod mcsettingsevents_parser;
pub mod mcstate_shared_profile_parser;
pub mod mobileactivation_parser;
pub mod mobilebackup_parser;
pub mod mobileinstallation_parser;
pub mod networkextension_parser;
pub mod networkextensioncache_parser;
pub mod netusage_parser;
pub mod olddsc_parser;
pub mod plists_parser;
pub mod powerlogs_parser;
pub mod ps_parser;
pub mod psthread_parser;
pub mod quarantine_events_parser;
pub mod remotectl_dumpstate_parser;
pub mod safari_history_parser;
pub mod security_sysdiagnose_parser;
pub mod screentime_parser;
pub mod shutdownlogs_parser;
pub mod spindumpnosymbols_parser;
pub mod swcutil_parser;
pub mod sys_parser;
pub mod taskinfo_parser;
pub mod transparency_json_parser;
pub mod transparency_parser;
pub mod uuid2path_parser;
pub mod wifi_known_networks_parser;
pub mod wifinetworks_parser;
pub mod wifiscan_parser;
pub mod wifisecurity_parser;

pub use accessibility_tcc_parser::AccessibilityTccParser;
pub use apollo_all_parser::ApolloAllParser;
pub use appinstallation_parser::AppinstallationParser;
pub use avconference_callsettings_parser::AvconferenceCallsettingsParser;
pub use battery_bdc_parser::BatteryBdcParser;
pub use brctl_parser::BrctlParser;
pub use containermanager_parser::ContainermanagerParser;
pub use crashlogs_parser::CrashlogsParser;
pub use disks_parser::DisksParser;
pub use dispatch::UniversalParser;
pub use ioacpiplane_parser::IoacpiplaneParser;
pub use iodevicetree_parser::IodevicetreeParser;
pub use iofirewire_parser::IofirewireParser;
pub use iopower_parser::IopowerParser;
pub use ioreg::IORegStructParser;
pub use ioservice_parser::IoserviceParser;
pub use iousb_parser::IousbParser;
pub use interactionc_parser::InteractioncParser;
pub use itunesstore_parser::ItunesstoreParser;
pub use kbdebug_parser::KbdebugParser;
pub use knowledgec_parser::KnowledgecParser;
pub use lockdownd_parser::LockdowndParser;
pub use logarchive_parser::LogarchiveParser;
pub use logdata_statistics_parser::LogdataStatisticsParser;
pub use logdata_statistics_txt_parser::LogdataStatisticsTxtParser;
pub use mcsettingsevents_parser::McsettingseventsParser;
pub use mcstate_shared_profile_parser::McstateSharedProfileParser;
pub use mobileactivation_parser::MobileactivationParser;
pub use mobilebackup_parser::MobilebackupParser;
pub use mobileinstallation_parser::MobileinstallationParser;
pub use networkextension_parser::NetworkextensionParser;
pub use networkextensioncache_parser::NetworkextensioncacheParser;
pub use netusage_parser::NetusageParser;
pub use olddsc_parser::OlddscParser;
pub use parser_events::{
    classify_ios_auth_message, f64_from_plist, parse_wifi_timestamp, stamp_auth_classification,
    wifi_network_dicts, AuthClassification,
};
pub use parser_helpers::MAX_UTF8_FILE;
pub use parse_options::{
    clamp_logarchive_decode_max_lines, default_logarchive_decode_max_lines, ParseOptions,
    LOGARCHIVE_FORENSIC_MAX_LINES,
};
pub use parser_type::ParserType;
pub use plists_parser::PlistsParser;
pub use powerlogs_parser::PowerlogsParser;
pub use ps_parser::PsParser;
pub use psthread_parser::PsThreadParser;
pub use quarantine_events_parser::QuarantineEventsParser;
pub use remotectl_dumpstate_parser::RemotectlDumpstateParser;
pub use safari_history_parser::SafariHistoryParser;
pub use security_sysdiagnose_parser::SecuritySysdiagnoseParser;
pub use screentime_parser::ScreentimeParser;
pub use shutdownlogs_parser::ShutdownLogsParser;
pub use spindumpnosymbols_parser::SpindumpnosymbolsParser;
pub use swcutil_parser::SwcutilParser;
pub use sys_parser::SystemVersionParser;
pub use taskinfo_parser::TaskinfoParser;
pub use transparency_json_parser::TransparencyJsonParser;
pub use transparency_parser::TransparencyParser;
pub use uuid2path_parser::Uuid2pathParser;
pub use wifi_known_networks_parser::WifiKnownNetworksParser;
pub use wifinetworks_parser::WifinetworksParser;
pub use wifiscan_parser::WifiscanParser;
pub use wifisecurity_parser::WifisecurityParser;

/// Parses one logical artifact inside a sysdiagnose bundle (aligned with SAF parser modules).
pub trait SysdiagnoseParser: Send + Sync {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>>;
}
