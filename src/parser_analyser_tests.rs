//! Smoke tests for every [`ParserType`] and [`AnalyserType`] on a minimal archive.
//!
//! Coverage is driven by `EnumIter` so new variants cannot be forgotten.
//! Deeper behaviour tests live under `parsers::*::tests` and `analysers::tests`.

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

#[test]
fn every_parser_runs_ok_on_minimal_archive() {
    let arch = minimal_archive();
    let mut failed = Vec::new();
    for pt in ParserType::iter() {
        if let Err(e) = parser_for(pt).parse(&arch) {
            failed.push(format!("{} ({:?}): {e}", pt.as_str(), pt));
        }
    }
    assert!(
        failed.is_empty(),
        "parsers failed on minimal archive:\n{}",
        failed.join("\n")
    );
}

#[test]
fn every_analyser_runs_ok_on_minimal_archive() {
    let arch = minimal_archive();
    let parsed = HashMap::new();
    let mut failed = Vec::new();
    for at in AnalyserType::iter() {
        match analyser_for(at).analyse(&arch, &parsed) {
            Ok(v) => {
                if v.get("analyser").and_then(|x| x.as_str()) != Some(at.as_str()) {
                    failed.push(format!(
                        "{}: expected analyser field {:?}, got {:?}",
                        at.as_str(),
                        at.as_str(),
                        v.get("analyser")
                    ));
                }
            }
            Err(e) => failed.push(format!("{} ({:?}): {e}", at.as_str(), at)),
        }
    }
    assert!(
        failed.is_empty(),
        "analysers failed on minimal archive:\n{}",
        failed.join("\n")
    );
}

#[test]
fn parser_type_enum_iter_matches_expected_count() {
    assert_eq!(ParserType::iter().count(), 67);
}

#[test]
fn analyser_type_enum_iter_matches_expected_count() {
    assert_eq!(AnalyserType::iter().count(), 15);
}

#[test]
fn parser_for_covers_every_parser_type() {
    for pt in ParserType::iter() {
        let _ = parser_for(pt);
    }
}

#[test]
fn analyser_for_covers_every_analyser_type() {
    for at in AnalyserType::iter() {
        let _ = analyser_for(at);
    }
}

#[test]
fn every_parser_as_str_roundtrips_via_from_str() {
    for pt in ParserType::iter() {
        let s = pt.as_str();
        let parsed: ParserType = s.parse().unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(parsed, pt, "FromStr mismatch for {s}");
        assert!(!pt.description().is_empty(), "{s} has empty description");
    }
}

#[test]
fn every_analyser_as_str_roundtrips_via_from_str() {
    for at in AnalyserType::iter() {
        let s = at.as_str();
        let parsed: AnalyserType = s.parse().unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(parsed, at, "FromStr mismatch for {s}");
        assert!(!at.description().is_empty(), "{s} has empty description");
    }
}

/// Sanity: smoke helpers still type-check against analyser JSON shape.
#[test]
fn coverage_analyser_returns_json_object() {
    let arch = minimal_archive();
    let parsed = HashMap::new();
    let v: Value = analyser_for(AnalyserType::coverage)
        .analyse(&arch, &parsed)
        .expect("coverage");
    assert!(v.is_object());
}
