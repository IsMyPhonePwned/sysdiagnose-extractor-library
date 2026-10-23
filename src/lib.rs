//! Rust library for parsing Apple **sysdiagnose** bundles distributed as `.tar.gz`.
//!
//! Design follows [`bugreport-extractor-library`](https://github.com/ping2A/bugreport-extractor-library):
//! load the artifact once, then run independent parsers in parallel.
//!
//! Parser IDs and behaviour mirror the Python SAF project
//! [EC-DIGIT-CSIRC/sysdiagnose](https://github.com/EC-DIGIT-CSIRC/sysdiagnose): every production
//! `parsers/*.py` module has a corresponding [`ParserType`] variant and a `*_parser.rs` module under
//! [`parsers`](parsers) (the upstream tutorial `demo_parser.py` is intentionally omitted). Some
//! parsers are full Rust ports; others export structured extracts (plist JSON, SQLite table dumps,
//! UTF-8 text, inventories) that match SAF inputs for downstream analysis. **`accessibility_tcc`**
//! and **`powerlogs`** run bundled SAF **APOLLO** SQL modules → jsonl-style `events`
//! (`src/parsers/apollo.rs`, crate-root `apollo_modules/`).
//!
//! [Sigma Zero](https://github.com/ping2A/sigmazero) rule evaluation over parser JSON is available
//! via [`detection::sigma`] and `sdx-cli parse --rules-dir …` (native targets only).
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use strum::IntoEnumIterator;
//! use sysdiagnose_extractor_library::archive::SysdiagnoseArchive;
//! use sysdiagnose_extractor_library::{parser_for_with_options, run_parsers_concurrently, ParseOptions, ParserType};
//!
//! let arch = Arc::new(SysdiagnoseArchive::open_path("sysdiagnose.tar.gz").unwrap());
//! let opts = ParseOptions { ioservice_full_tree: false, ..Default::default() };
//! let parsers: Vec<_> = [ParserType::ps, ParserType::ioservice]
//!     .into_iter()
//!     .map(|t| (t, parser_for_with_options(t, opts.clone())))
//!     .collect();
//! let _ = run_parsers_concurrently(arch, parsers);
//! ```

use serde_json::Value;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use rayon::prelude::*;
use strum::IntoEnumIterator;

pub mod analysers;
pub mod archive;
pub mod detection;
pub mod error;
pub mod file_loader;
pub mod glob_match;
pub mod parsers;
mod sqlite_dump;
mod tab_hierarchy;
pub mod util;

pub use analysers::{
    all_analyser_types, analyser_for, arc_value, canonicalize_app_bundle_id,
    extract_app_bundle_id_from_text, is_likely_app_bundle_id, Analyser, AnalyserType,
    BuiltinAnalyser, ParsedByParser,
};
pub use archive::{parse_bundle_acquisition, ArchiveOptions, SysdiagnoseArchive};
pub use error::ArchiveError;
pub use parsers::{ParseOptions, ParserType, SysdiagnoseParser, UniversalParser};
pub use util::{
    enrich_mobile_installation_event, looks_like_app_version, parse_mobile_install_versions,
    MobileInstallVersions,
};

/// Build a parser instance for [`ParserType`] (dispatches all parser modules).
pub fn parser_for(t: ParserType) -> Box<dyn SysdiagnoseParser + Send + Sync> {
    parser_for_with_options(t, ParseOptions::default())
}

/// Build a parser with [`ParseOptions`] (e.g. `ioservice_full_tree`).
pub fn parser_for_with_options(
    t: ParserType,
    options: ParseOptions,
) -> Box<dyn SysdiagnoseParser + Send + Sync> {
    Box::new(UniversalParser::with_options(t, options))
}

/// Run parsers in parallel over a shared [`SysdiagnoseArchive`].
///
/// Successful results are wrapped in [`Arc`] so callers can share JSON with analysers / Sigma
/// without deep-cloning large trees.
pub fn run_parsers_concurrently(
    archive: Arc<SysdiagnoseArchive>,
    parsers_to_run: Vec<(ParserType, Box<dyn SysdiagnoseParser + Send + Sync>)>,
) -> Vec<(
    ParserType,
    Result<Arc<Value>, Box<dyn Error + Send + Sync>>,
    Duration,
)> {
    parsers_to_run
        .into_par_iter()
        .map(|(parser_type, parser)| {
            let arch = Arc::clone(&archive);
            // `std::time::Instant` is not implemented on wasm32-unknown-unknown (panics).
            #[cfg(target_arch = "wasm32")]
            let (result, duration) = {
                let result = parser.parse(arch.as_ref()).map(Arc::new);
                (result, Duration::ZERO)
            };
            #[cfg(not(target_arch = "wasm32"))]
            let (result, duration) = {
                let start = std::time::Instant::now();
                let result = parser.parse(arch.as_ref()).map(Arc::new);
                (result, start.elapsed())
            };
            (parser_type, result, duration)
        })
        .collect()
}

/// All parser module IDs (aligned with upstream `sysdiag list parsers` where applicable).
pub fn all_parser_types() -> Vec<ParserType> {
    ParserType::iter().collect()
}

#[cfg(test)]
mod parser_analyser_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_core_parsers_on_minimal_archive() {
        use std::collections::HashMap;
        let mut m = HashMap::new();
        let ps_bytes: Vec<u8> = b"USER PID\n1 1\n".to_vec();
        m.insert("ps.txt".to_string(), Arc::from(ps_bytes.into_boxed_slice()));
        let arch = Arc::new(SysdiagnoseArchive::from_files_for_test(m));
        let parsers: Vec<_> = [ParserType::ps, ParserType::sys, ParserType::taskinfo]
            .into_iter()
            .map(|t| (t, parser_for(t)))
            .collect();
        let results = run_parsers_concurrently(arch, parsers);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn all_parser_types_count_is_53() {
        assert_eq!(all_parser_types().len(), 53);
    }
}
