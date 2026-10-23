//! Dispatch every parser module to a Rust implementation (full or structured extract).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_type::ParserType;
use crate::parsers::{
    AccessibilityTccParser, ApolloAllParser, AppinstallationParser, AvconferenceCallsettingsParser,
    AwdBasebandParser, BatteryBdcParser, BluetoothParser, BrctlParser, CkksPcsParser,
    CollectionMetaParser, ContainermanagerParser, CrashlogsParser, DisksParser, InteractioncParser,
    IoacpiplaneParser, IodevicetreeParser, IofirewireParser, IoportParser, IopowerParser,
    IoserviceParser, IousbParser, ItunesstoreParser, KbdebugParser, KnowledgecParser,
    LockdowndParser, LogarchiveParser, LogdataStatisticsParser, LogdataStatisticsTxtParser,
    LsawParser, McsettingseventsParser, McstateSharedProfileParser, MicrostackshotsParser,
    MobileactivationParser, MobilebackupParser, MobileinstallationParser, MountParser,
    NetusageParser, NetworkextensionParser, NetworkextensioncacheParser, OlddscParser,
    OtaUpdateParser, ParseOptions, PlistsParser, PowerlogsParser, PreferencesParser, PsParser,
    PsThreadParser, QuarantineEventsParser, RemotectlDumpstateParser, RunningboardParser,
    SafariHistoryParser, ScreentimeParser, SecuritySysdiagnoseParser, ShutdownLogsParser,
    SpindumpnosymbolsParser, SwcutilParser, SysdiagnoseParser, SystemStatsParser,
    SystemVersionParser, TaskinfoParser, TransparencyJsonParser, TransparencyParser,
    UsermanagementParser, Uuid2pathParser, WifiDiagnosticsParser, WifiKnownNetworksParser,
    WifinetworksParser, WifiscanParser, WifisecurityParser,
};

#[derive(Clone)]
pub struct UniversalParser {
    pub parser_type: ParserType,
    pub options: ParseOptions,
}

impl UniversalParser {
    pub fn new(parser_type: ParserType) -> Self {
        Self {
            parser_type,
            options: ParseOptions::default(),
        }
    }

    pub fn with_options(parser_type: ParserType, options: ParseOptions) -> Self {
        Self {
            parser_type,
            options,
        }
    }
}

impl SysdiagnoseParser for UniversalParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        match self.parser_type {
            ParserType::accessibility_tcc => AccessibilityTccParser.parse(archive),
            ParserType::apollo_all => ApolloAllParser.parse(archive),
            ParserType::appinstallation => AppinstallationParser.parse(archive),
            ParserType::avconference_callsettings => AvconferenceCallsettingsParser.parse(archive),
            ParserType::awd_baseband => AwdBasebandParser.parse(archive),
            ParserType::battery_bdc => BatteryBdcParser.parse(archive),
            ParserType::bluetooth => BluetoothParser.parse(archive),
            ParserType::brctl => BrctlParser.parse(archive),
            ParserType::ckks_pcs => CkksPcsParser.parse(archive),
            ParserType::collection_meta => CollectionMetaParser.parse(archive),
            ParserType::containermanager => ContainermanagerParser.parse(archive),
            ParserType::crashlogs => CrashlogsParser.parse(archive),
            ParserType::disks => DisksParser.parse(archive),
            ParserType::ioacpiplane => IoacpiplaneParser.parse(archive),
            ParserType::iodevicetree => IodevicetreeParser.parse(archive),
            ParserType::iofirewire => IofirewireParser.parse(archive),
            ParserType::iopower => IopowerParser.parse(archive),
            ParserType::ioservice => IoserviceParser.parse_with_options(archive, &self.options),
            ParserType::iousb => IousbParser.parse(archive),
            ParserType::interactionc => InteractioncParser.parse(archive),
            ParserType::ioport => IoportParser.parse(archive),
            ParserType::itunesstore => ItunesstoreParser.parse(archive),
            ParserType::kbdebug => KbdebugParser.parse(archive),
            ParserType::knowledgec => KnowledgecParser.parse(archive),
            ParserType::lockdownd => LockdowndParser.parse(archive),
            ParserType::logarchive => LogarchiveParser.parse_with_options(archive, &self.options),
            ParserType::logdata_statistics => LogdataStatisticsParser.parse(archive),
            ParserType::logdata_statistics_txt => LogdataStatisticsTxtParser.parse(archive),
            ParserType::lsaw => LsawParser.parse(archive),
            ParserType::mcsettingsevents => McsettingseventsParser.parse(archive),
            ParserType::mcstate_shared_profile => McstateSharedProfileParser.parse(archive),
            ParserType::microstackshots => MicrostackshotsParser.parse(archive),
            ParserType::mobileactivation => MobileactivationParser.parse(archive),
            ParserType::mobilebackup => MobilebackupParser.parse(archive),
            ParserType::mobileinstallation => MobileinstallationParser.parse(archive),
            ParserType::mount => MountParser.parse(archive),
            ParserType::networkextension => NetworkextensionParser.parse(archive),
            ParserType::networkextensioncache => NetworkextensioncacheParser.parse(archive),
            ParserType::netusage => NetusageParser.parse(archive),
            ParserType::olddsc => OlddscParser.parse(archive),
            ParserType::ota_update => OtaUpdateParser.parse(archive),
            ParserType::plists => PlistsParser.parse(archive),
            ParserType::powerlogs => PowerlogsParser.parse(archive),
            ParserType::preferences => PreferencesParser.parse(archive),
            ParserType::ps => PsParser.parse(archive),
            ParserType::psthread => PsThreadParser.parse(archive),
            ParserType::quarantine_events => QuarantineEventsParser.parse(archive),
            ParserType::remotectl_dumpstate => RemotectlDumpstateParser.parse(archive),
            ParserType::runningboard => RunningboardParser.parse(archive),
            ParserType::safari_history => SafariHistoryParser.parse(archive),
            ParserType::security_sysdiagnose => SecuritySysdiagnoseParser.parse(archive),
            ParserType::screentime => ScreentimeParser.parse(archive),
            ParserType::shutdownlogs => ShutdownLogsParser.parse(archive),
            ParserType::spindumpnosymbols => SpindumpnosymbolsParser.parse(archive),
            ParserType::swcutil => SwcutilParser.parse(archive),
            ParserType::sys => SystemVersionParser.parse(archive),
            ParserType::system_stats => SystemStatsParser.parse(archive),
            ParserType::taskinfo => TaskinfoParser.parse(archive),
            ParserType::transparency => TransparencyParser.parse(archive),
            ParserType::transparency_json => TransparencyJsonParser.parse(archive),
            ParserType::usermanagement => UsermanagementParser.parse(archive),
            ParserType::uuid2path => Uuid2pathParser.parse(archive),
            ParserType::wifi_diagnostics => WifiDiagnosticsParser.parse(archive),
            ParserType::wifi_known_networks => WifiKnownNetworksParser.parse(archive),
            ParserType::wifinetworks => WifinetworksParser.parse(archive),
            ParserType::wifiscan => WifiscanParser.parse(archive),
            ParserType::wifisecurity => WifisecurityParser.parse(archive),
        }
    }
}
