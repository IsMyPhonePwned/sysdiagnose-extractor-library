//! Wi‑Fi / network diagnostic text dumps (`ifconfig`, ARP, netstat, status, …).

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::text_files_result;
use crate::parsers::SysdiagnoseParser;

pub struct WifiDiagnosticsParser;

impl SysdiagnoseParser for WifiDiagnosticsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        text_files_result(
            archive,
            "wifi_diagnostics",
            &[
                "WiFi/ifconfig.txt",
                "WiFi/arp.txt",
                "WiFi/netstat-PRE.txt",
                "WiFi/netstat-POST.txt",
                "WiFi/network_status.txt",
                "WiFi/wifi_status.txt",
                "WiFi/diagnostics-*.txt",
                "WiFi/leaky_ap_stats.txt",
            ],
            64,
        )
    }
}
