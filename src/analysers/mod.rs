//! Analysers consume parser JSON (and the archive when a parser output is missing).
//!
//! Pass the map of `parser_id →` raw [`serde_json::Value`] from each parser run (same shape as
//! `UniversalParser` / `parser_for` output). Missing keys cause the analyser to re-parse only what
//! it needs from the archive.
//!
//! Layout: one module per analyser (`apps`, `coverage`, …), shared helpers in `common`, and
//! `dispatch` to route [`AnalyserType`] to each `run`.

mod accounts;
mod apps;
mod common;
mod coverage;
mod dispatch;
mod file_stats;
mod install_enrichment;
mod mcstateshared;
mod network_iocs;
mod permissions;
mod plist;
mod ps_everywhere;
mod ps_matrix;
mod summary;
mod timesketch;
mod wifi_geolocation;
mod wifi_geolocation_kml;

use crate::archive::SysdiagnoseArchive;
use serde_json::Value;
use std::error::Error;
use std::str::FromStr;

pub use common::{
    arc_value, canonicalize_app_bundle_id, extract_app_bundle_id_from_text, is_likely_app_bundle_id,
    ParsedByParser,
};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum AnalyserType {
    accounts,
    apps,
    coverage,
    file_stats,
    install_enrichment,
    mcstateshared,
    network_iocs,
    permissions,
    plist,
    ps_everywhere,
    ps_matrix,
    summary,
    timesketch,
    wifi_geolocation,
    wifi_geolocation_kml,
}

impl AnalyserType {
    pub fn as_str(self) -> &'static str {
        match self {
            AnalyserType::accounts => "accounts",
            AnalyserType::apps => "apps",
            AnalyserType::coverage => "coverage",
            AnalyserType::file_stats => "file_stats",
            AnalyserType::install_enrichment => "install_enrichment",
            AnalyserType::mcstateshared => "mcstateshared",
            AnalyserType::network_iocs => "network_iocs",
            AnalyserType::permissions => "permissions",
            AnalyserType::plist => "plist",
            AnalyserType::ps_everywhere => "ps_everywhere",
            AnalyserType::ps_matrix => "ps_matrix",
            AnalyserType::summary => "summary",
            AnalyserType::timesketch => "timesketch",
            AnalyserType::wifi_geolocation => "wifi_geolocation",
            AnalyserType::wifi_geolocation_kml => "wifi_geolocation_kml",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            AnalyserType::accounts => {
                "Device-user identity: calendar owner emails, transparency contacts, Apple account keys, linked devices"
            }
            AnalyserType::apps => "Get list of Apps installed on the device",
            AnalyserType::coverage => "Coverage report for parsers",
            AnalyserType::file_stats => "File statistics",
            AnalyserType::install_enrichment => {
                "Correlate installs/deletes with nearby IPA / sideload-tool activity"
            }
            AnalyserType::mcstateshared => "MCState shared profile analyser",
            AnalyserType::network_iocs => {
                "Heuristic IPv4 / domain / URL extraction from parser JSON"
            }
            AnalyserType::permissions => "TCC privacy permissions per app bundle id",
            AnalyserType::plist => "Plist analyser",
            AnalyserType::ps_everywhere => "List all processes we can find a bit everywhere",
            AnalyserType::ps_matrix => "Matrix comparing ps, psthread, taskinfo",
            AnalyserType::summary => "Summary across key parsers",
            AnalyserType::timesketch => "Timeline rows for Timesketch import (CSV + JSON)",
            AnalyserType::wifi_geolocation => "GPX from WiFi geolocations",
            AnalyserType::wifi_geolocation_kml => "KML from WiFi geolocations",
        }
    }
}

impl FromStr for AnalyserType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().replace('-', "_").as_str() {
            "accounts" => Ok(AnalyserType::accounts),
            "apps" => Ok(AnalyserType::apps),
            "coverage" => Ok(AnalyserType::coverage),
            "file_stats" => Ok(AnalyserType::file_stats),
            "install_enrichment" => Ok(AnalyserType::install_enrichment),
            "mcstateshared" => Ok(AnalyserType::mcstateshared),
            "network_iocs" => Ok(AnalyserType::network_iocs),
            "permissions" => Ok(AnalyserType::permissions),
            "plist" => Ok(AnalyserType::plist),
            "ps_everywhere" => Ok(AnalyserType::ps_everywhere),
            "ps_matrix" => Ok(AnalyserType::ps_matrix),
            "summary" => Ok(AnalyserType::summary),
            "timesketch" => Ok(AnalyserType::timesketch),
            "wifi_geolocation" => Ok(AnalyserType::wifi_geolocation),
            "wifi_geolocation_kml" => Ok(AnalyserType::wifi_geolocation_kml),
            _ => Err(format!("unknown analyser: {s}")),
        }
    }
}

pub trait Analyser: Send + Sync {
    /// `parsed` maps parser module id (e.g. `"ps"`) to that parser's JSON output.
    fn analyse(
        &self,
        archive: &SysdiagnoseArchive,
        parsed: &ParsedByParser,
    ) -> Result<Value, Box<dyn Error + Send + Sync>>;
}

/// Dispatches to the built-in implementation for each [`AnalyserType`].
pub struct BuiltinAnalyser(pub AnalyserType);

impl Analyser for BuiltinAnalyser {
    fn analyse(
        &self,
        archive: &SysdiagnoseArchive,
        parsed: &ParsedByParser,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        dispatch::run(self.0, archive, parsed)
    }
}

/// Boxed analyser instance for dynamic dispatch.
pub fn analyser_for(t: AnalyserType) -> Box<dyn Analyser> {
    Box::new(BuiltinAnalyser(t))
}

pub fn all_analyser_types() -> Vec<AnalyserType> {
    use strum::IntoEnumIterator;
    AnalyserType::iter().collect()
}

#[cfg(test)]
mod tests;
