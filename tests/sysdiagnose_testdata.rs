//! Integration with upstream archives from
//! [EC-DIGIT-CSIRC/sysdiagnose-testdata](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata)
//! (pin **`7e64d5ca133837393c0c7cd3193d0d4dcabc5447`**).
//!
//! # Layout
//!
//! 1. Environment variable **`SYSDIAGNOSE_TESTDATA`**: absolute path, or relative to the crate
//!    root (`CARGO_MANIFEST_DIR`), to the checkout root (the folder that contains `iOS15/` /
//!    `iOS16/` and the `*.tar.gz` members).
//! 2. Otherwise **`testdata/sysdiagnose-testdata/`** under this crate (typical: `git clone` that
//!    repo here, then **`git lfs pull`** — blobs in Git are LFS pointer files until then).
//!
//! # Behaviour
//!
//! - Recursively collects **`*.tar.gz`**, skips **Git LFS pointer** stubs (tiny text files), then
//!   runs **every** [`ParserType`] on each real archive (same idea as `integration_assets`).
//! - If the directory is missing or only pointers are present, the test **passes** after printing
//!   a skip hint (so `cargo test` works in fresh clones).
//! - Set **`SYSDIAGNOSE_TESTDATA_REQUIRE=1`** (or `true` / `yes`) to **fail** when no usable
//!   archive is found (for a CI job that installs LFS objects).
//!
//! ## SAF jsonl shape ([`SysdiagnoseTestCase.required_fields_jsonl`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/__init__.py))
//!
//! For parser output with **`format: "jsonl"`** (from [`wrap_jsonl`](https://github.com/ismyphonepwned/sysdiagnose-extractor-library/blob/main/src/parsers/parser_events/common.rs)),
//! every entry in **`events`** must include **`message`**, **`datetime`**, **`timestamp_desc`**, and **`module`**
//! (mirrors upstream `assert_has_required_fields_jsonl`).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sysdiagnose_extractor_library::{
    all_parser_types, parser_for, run_parsers_concurrently, ParserType, SysdiagnoseArchive,
};

const UPSTREAM_TESTDATA_PIN: &str = "7e64d5ca133837393c0c7cd3193d0d4dcabc5447";

/// Same field list as upstream [`SysdiagnoseTestCase.required_fields_jsonl`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/tests/__init__.py).
const REQUIRED_JSONL_FIELDS: &[&str] = &["message", "datetime", "timestamp_desc", "module"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn testdata_root() -> PathBuf {
    if let Ok(p) = std::env::var("SYSDIAGNOSE_TESTDATA") {
        let p = p.trim();
        if !p.is_empty() {
            let path = PathBuf::from(p);
            return if path.is_absolute() {
                path
            } else {
                manifest_dir().join(path)
            };
        }
    }
    manifest_dir().join("testdata/sysdiagnose-testdata")
}

fn require_usable_archives() -> bool {
    matches!(
        std::env::var("SYSDIAGNOSE_TESTDATA_REQUIRE")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("TRUE") | Some("YES")
    )
}

fn is_git_lfs_pointer(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() > 512 {
        return false;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let Ok(s) = std::str::from_utf8(&bytes) else {
        return false;
    };
    s.starts_with("version https://git-lfs.github.com/spec/v1")
}

fn is_tar_gz_path(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("gz"))
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".tar.gz"))
}

fn collect_tar_gz(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_dir() {
            collect_tar_gz(&p, out);
        } else if ft.is_file() && is_tar_gz_path(&p) {
            out.push(p);
        }
    }
}

fn usable_archives(root: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    collect_tar_gz(root, &mut v);
    v.retain(|p| !is_git_lfs_pointer(p));
    v.sort();
    v
}

/// Returns `None` when tests should skip (and print a hint), or `Some(archives)`.
fn resolve_archives() -> Option<Vec<PathBuf>> {
    let root = testdata_root();
    if !root.is_dir() {
        let msg = format!(
            "sysdiagnose-testdata not found at {} — clone \
             https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata.git \
             (commit {UPSTREAM_TESTDATA_PIN}) into testdata/sysdiagnose-testdata \
             and run git lfs pull, or set SYSDIAGNOSE_TESTDATA",
            root.display()
        );
        if require_usable_archives() {
            panic!("{msg}");
        }
        eprintln!("skip: {msg}");
        return None;
    }

    let archives = usable_archives(&root);
    if archives.is_empty() {
        let msg = format!(
            "no usable *.tar.gz under {} (only Git LFS pointers? run `git lfs pull` in the testdata repo; pin {UPSTREAM_TESTDATA_PIN})",
            root.display()
        );
        if require_usable_archives() {
            panic!("{msg}");
        }
        eprintln!("skip: {msg}");
        return None;
    }

    Some(archives)
}

fn run_all_parsers_on_archive(
    path: &Path,
) -> Vec<(
    ParserType,
    Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>,
    std::time::Duration,
)> {
    let arch = Arc::new(
        SysdiagnoseArchive::open_path(path)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display())),
    );
    let types = all_parser_types();
    let parsers: Vec<_> = types.into_iter().map(|t| (t, parser_for(t))).collect();
    run_parsers_concurrently(arch, parsers)
}

fn assert_wrap_jsonl_required_fields(parser: ParserType, v: &serde_json::Value) {
    if v.get("format").and_then(|x| x.as_str()) != Some("jsonl") {
        return;
    }
    let Some(events) = v.get("events").and_then(|e| e.as_array()) else {
        return;
    };
    if events.is_empty() {
        return;
    }
    for (i, ev) in events.iter().enumerate() {
        let Some(obj) = ev.as_object() else {
            panic!("{parser:?} jsonl events[{i}] is not an object: {ev:?}");
        };
        for field in REQUIRED_JSONL_FIELDS {
            let Some(val) = obj.get(*field) else {
                panic!(
                    "{parser:?} jsonl events[{i}] missing required field `{field}` (upstream SysdiagnoseTestCase.required_fields_jsonl): {ev:?}"
                );
            };
            assert!(
                !val.is_null(),
                "{parser:?} jsonl events[{i}] field `{field}` is null: {ev:?}"
            );
            assert!(
                val.is_string(),
                "{parser:?} jsonl events[{i}] field `{field}` must be a string: {ev:?}"
            );
        }
    }
}

#[test]
fn upstream_sysdiagnose_testdata_all_parsers_ok() {
    let Some(archives) = resolve_archives() else {
        return;
    };

    eprintln!(
        "sysdiagnose-testdata: running all parsers on {} archive(s)",
        archives.len(),
    );

    for path in &archives {
        eprintln!("  … {}", path.display());
        let results = run_all_parsers_on_archive(path);
        for (pt, res, _) in &results {
            res.as_ref()
                .unwrap_or_else(|e| panic!("parser {pt:?} failed on {}: {e}", path.display()));
        }
    }

    // Light sanity check on the first archive (real bundles ship ps.txt).
    let arch0 = Arc::new(
        SysdiagnoseArchive::open_path(&archives[0])
            .expect("re-open first archive for smoke checks"),
    );
    let parsers: Vec<_> = [ParserType::ps, ParserType::sys]
        .into_iter()
        .map(|t| (t, parser_for(t)))
        .collect();
    let smoke = run_parsers_concurrently(arch0, parsers);
    let ps = smoke
        .iter()
        .find(|(t, _, _)| *t == ParserType::ps)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    let rows = ps["rows"].as_array().expect("ps rows array");
    assert!(
        rows.len() > 5,
        "expected several processes in testdata archive {}",
        archives[0].display()
    );
}

#[test]
fn upstream_sysdiagnose_testdata_wrap_jsonl_required_fields() {
    let Some(archives) = resolve_archives() else {
        return;
    };

    eprintln!(
        "sysdiagnose-testdata: required_fields_jsonl on wrap_jsonl outputs, {} archive(s)",
        archives.len(),
    );

    for path in &archives {
        eprintln!("  … {}", path.display());
        let results = run_all_parsers_on_archive(path);
        for (pt, res, _) in &results {
            let v = res
                .as_ref()
                .unwrap_or_else(|e| panic!("parser {pt:?} failed on {}: {e}", path.display()));
            assert_wrap_jsonl_required_fields(*pt, v);
        }
    }
}
