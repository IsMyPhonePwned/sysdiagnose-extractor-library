//! Dispatches [`super::AnalyserType`] to per-module `run` implementations.

use serde_json::Value;
use std::error::Error;

use crate::archive::SysdiagnoseArchive;

use super::common::ParsedByParser;
use super::AnalyserType;
use super::{
    accounts, apps, coverage, file_stats, install_enrichment, mcstateshared, network_iocs,
    permissions, plist, ps_everywhere, ps_matrix, summary,
};
use super::{timesketch, wifi_geolocation, wifi_geolocation_kml};

pub fn run(
    analyser: AnalyserType,
    archive: &SysdiagnoseArchive,
    parsed: &ParsedByParser,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let v = match analyser {
        AnalyserType::accounts => accounts::run(parsed, archive),
        AnalyserType::coverage => coverage::run(parsed, archive),
        AnalyserType::file_stats => file_stats::run(parsed, archive),
        AnalyserType::apps => apps::run(parsed, archive),
        AnalyserType::install_enrichment => install_enrichment::run(parsed, archive),
        AnalyserType::mcstateshared => mcstateshared::run(parsed, archive),
        AnalyserType::network_iocs => network_iocs::run(parsed, archive),
        AnalyserType::permissions => permissions::run(parsed, archive),
        AnalyserType::plist => plist::run(parsed, archive),
        AnalyserType::ps_everywhere => ps_everywhere::run(parsed, archive),
        AnalyserType::ps_matrix => ps_matrix::run(parsed, archive),
        AnalyserType::summary => summary::run(parsed, archive),
        AnalyserType::timesketch => timesketch::run(parsed, archive),
        AnalyserType::wifi_geolocation => wifi_geolocation::run(parsed, archive),
        AnalyserType::wifi_geolocation_kml => wifi_geolocation_kml::run(parsed, archive),
    };
    Ok(v)
}
