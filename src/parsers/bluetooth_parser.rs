//! Bluetooth / AWDL / companion-link status text.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parser_helpers::text_files_result;
use crate::parsers::SysdiagnoseParser;

pub struct BluetoothParser;

impl SysdiagnoseParser for BluetoothParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, Box<dyn Error + Send + Sync>> {
        text_files_result(
            archive,
            "bluetooth",
            &[
                "WiFi/bluetooth_status.txt",
                "WiFi/awdl_status.txt",
                "logs/Bluetooth/**",
                "logs/NetworkRelay/companion_link_status*.txt",
            ],
            128,
        )
    }
}
