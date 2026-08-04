//! Unified-log decode for `system_logs.logarchive/` via `sysdiagnose_logarchive_decode`.

use serde_json::{json, Value};

use crate::archive::SysdiagnoseArchive;
use crate::parsers::parse_options::default_logarchive_decode_max_lines;

#[cfg(not(target_arch = "wasm32"))]
const LOGARCHIVE_PREFIX: &str = "system_logs.logarchive/";

#[cfg(all(not(target_arch = "wasm32"), feature = "logarchive-decode"))]
use crate::parsers::parser_events::saf_event_dict;

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

/// Materialize `system_logs.logarchive/` from the in-memory archive to a temp `.logarchive` bundle.
#[cfg(not(target_arch = "wasm32"))]
pub fn materialize_logarchive(
    archive: &SysdiagnoseArchive,
) -> Result<(tempfile::TempDir, PathBuf), String> {
    materialize_logarchive_with_progress(archive, None)
}

/// Same as [`materialize_logarchive`], reporting file counts as they are written.
#[cfg(not(target_arch = "wasm32"))]
pub fn materialize_logarchive_with_progress(
    archive: &SysdiagnoseArchive,
    mut on_progress: Option<&mut dyn FnMut(usize)>,
) -> Result<(tempfile::TempDir, PathBuf), String> {
    let tmp = tempfile::Builder::new()
        .prefix("sysdiagnose_")
        .suffix(".logarchive")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let root = tmp.path().to_path_buf();
    let mut wrote = 0usize;
    let mut last_report = std::time::Instant::now();

    let report = |cb: &mut Option<&mut dyn FnMut(usize)>, n: usize, last: &mut std::time::Instant| {
        let Some(cb) = cb.as_mut() else {
            return;
        };
        if n == 1 || n % 25 == 0 || last.elapsed() >= std::time::Duration::from_millis(400) {
            cb(n);
            *last = std::time::Instant::now();
        }
    };

    // Link/copy spilled Persist/*.tracev3 (and other heavy members) without re-buffering in RAM.
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(spill_root) = archive.logarchive_spill_dir() {
        for (path, _) in archive.logarchive_spilled_entries() {
            let Some(under) = path.strip_prefix(LOGARCHIVE_PREFIX) else {
                continue;
            };
            if under.is_empty() {
                continue;
            }
            let src = spill_root.join(under);
            let dest = root.join(under);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            if std::fs::hard_link(&src, &dest).is_err() {
                std::fs::copy(&src, &dest).map_err(|e| e.to_string())?;
            }
            wrote += 1;
            report(&mut on_progress, wrote, &mut last_report);
        }
    }

    for (path, bytes) in archive.iter_files() {
        if !path.starts_with(LOGARCHIVE_PREFIX) {
            continue;
        }
        let rel = &path[LOGARCHIVE_PREFIX.len()..];
        if rel.is_empty() {
            continue;
        }
        let dest = root.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;
        wrote += 1;
        report(&mut on_progress, wrote, &mut last_report);
    }
    if wrote == 0 {
        return Err("no files under system_logs.logarchive/ in archive".into());
    }
    if let Some(cb) = on_progress.as_mut() {
        cb(wrote);
    }
    Ok((tmp, root))
}

#[cfg(feature = "logarchive-decode")]
#[cfg(not(target_arch = "wasm32"))]
fn unified_rows_to_events(rows: Vec<sysdiagnose_logarchive_decode::UnifiedLogEvent>) -> Vec<Value> {
    use crate::parsers::parser_events::{classify_ios_auth_message, stamp_auth_classification};

    rows.into_iter()
        .map(|u| {
            let mut data = serde_json::Map::new();
            data.insert("subsystem".into(), json!(u.subsystem));
            data.insert("category".into(), json!(u.category));
            data.insert("process".into(), json!(u.process));
            data.insert("threadID".into(), json!(u.thread_id));
            data.insert("eventType".into(), json!(u.event_type));
            data.insert("eventMessage".into(), json!(u.message.clone()));
            data.insert("message".into(), json!(u.message.clone()));
            data.insert("timestamp".into(), json!(u.timestamp));
            data.insert("pid".into(), json!(u.pid));
            data.insert("library".into(), json!(u.library));
            data.insert("evidence".into(), json!(u.evidence));

            let mut timestamp_desc = "Unified Log".to_string();
            if let Some(auth) = classify_ios_auth_message(&u.message) {
                stamp_auth_classification(&mut data, auth);
                timestamp_desc = auth.timestamp_desc.to_string();
            }

            saf_event_dict(
                "logarchive",
                u.datetime,
                &timestamp_desc,
                &u.message,
                Value::Object(data),
            )
        })
        .collect()
}

/// Live progress for [`decode_logarchive_events_with_limit_and_progress`].
#[derive(Debug, Clone)]
pub struct LogarchiveDecodeProgress {
    pub phase: &'static str,
    pub detail: Option<String>,
    pub max_lines: Option<usize>,
    pub events_decoded: Option<usize>,
    pub files_materialized: Option<usize>,
    pub tracev3_files: Option<usize>,
    pub current_file: Option<String>,
}

impl Default for LogarchiveDecodeProgress {
    fn default() -> Self {
        Self {
            phase: "",
            detail: None,
            max_lines: None,
            events_decoded: None,
            files_materialized: None,
            tracev3_files: None,
            current_file: None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn decode_inner(
    archive: &SysdiagnoseArchive,
    max_lines: usize,
    mut on_progress: Option<&mut dyn FnMut(LogarchiveDecodeProgress)>,
) -> (Value, Vec<Value>) {
    let emit = |cb: &mut Option<&mut dyn FnMut(LogarchiveDecodeProgress)>, p: LogarchiveDecodeProgress| {
        if let Some(cb) = cb.as_mut() {
            cb(p);
        }
    };

    // Without the decode feature, never materialize (avoids writing multi‑GB temp trees).
    #[cfg(not(feature = "logarchive-decode"))]
    {
        let _ = archive;
        emit(
            &mut on_progress,
            LogarchiveDecodeProgress {
                phase: "deferred",
                detail: Some("enable Cargo feature logarchive-decode".into()),
                max_lines: Some(max_lines),
                ..Default::default()
            },
        );
        return (
            json!({
                "status": "deferred",
                "reason": "enable Cargo feature logarchive-decode",
                "max_lines": max_lines,
            }),
            Vec::new(),
        );
    }

    #[cfg(feature = "logarchive-decode")]
    {
    emit(
        &mut on_progress,
        LogarchiveDecodeProgress {
            phase: "materializing",
            detail: Some("Writing system_logs.logarchive/ to temp dir…".into()),
            max_lines: Some(max_lines),
            ..Default::default()
        },
    );

    let mut files_materialized = 0usize;
    let (tmpdir, materialized) = {
        let mut mat_cb = |n: usize| {
            files_materialized = n;
            emit(
                &mut on_progress,
                LogarchiveDecodeProgress {
                    phase: "materializing",
                    detail: Some(format!("Materializing logarchive… {n} files written")),
                    max_lines: Some(max_lines),
                    files_materialized: Some(n),
                    ..Default::default()
                },
            );
        };
        match materialize_logarchive_with_progress(archive, Some(&mut mat_cb)) {
            Ok(v) => v,
            Err(reason) => {
                emit(
                    &mut on_progress,
                    LogarchiveDecodeProgress {
                        phase: "skipped",
                        detail: Some(reason.clone()),
                        max_lines: Some(max_lines),
                        ..Default::default()
                    },
                );
                return (
                    json!({
                        "status": "skipped",
                        "reason": reason,
                    }),
                    Vec::new(),
                );
            }
        }
    };

        if !sysdiagnose_logarchive_decode::logarchive_has_tracev3(&materialized) {
            drop(tmpdir);
            let detail = "no tracev3 files under system_logs.logarchive/ (incomplete bundle or members skipped by --max-entry-mb)".to_string();
            emit(
                &mut on_progress,
                LogarchiveDecodeProgress {
                    phase: "skipped",
                    detail: Some(detail.clone()),
                    max_lines: Some(max_lines),
                    files_materialized: Some(files_materialized),
                    ..Default::default()
                },
            );
            return (
                json!({
                    "status": "skipped",
                    "reason": detail,
                    "max_lines": max_lines,
                }),
                Vec::new(),
            );
        }

        emit(
            &mut on_progress,
            LogarchiveDecodeProgress {
                phase: "decoding",
                detail: Some(format!("Decoding unified logs (cap {max_lines} lines)…")),
                max_lines: Some(max_lines),
                files_materialized: Some(files_materialized),
                events_decoded: Some(0),
                ..Default::default()
            },
        );

        let mut decode_cb = |events: usize, path: &str, files: usize| {
            let short = path.rsplit('/').next().unwrap_or(path);
            emit(
                &mut on_progress,
                LogarchiveDecodeProgress {
                    phase: "decoding",
                    detail: Some(if path.is_empty() {
                        format!("Decoded {events} events from {files} tracev3 files")
                    } else {
                        format!("Decoded {events}/{max_lines} events · {files} tracev3 · {short}")
                    }),
                    max_lines: Some(max_lines),
                    files_materialized: Some(files_materialized),
                    events_decoded: Some(events),
                    tracev3_files: Some(files),
                    current_file: if path.is_empty() {
                        None
                    } else {
                        Some(short.to_string())
                    },
                    ..Default::default()
                },
            );
        };

        match sysdiagnose_logarchive_decode::decode_logarchive_dir_with_progress(
            &materialized,
            max_lines,
            Some(&mut decode_cb),
        ) {
            Ok(rows) => {
                let events = unified_rows_to_events(rows);
                drop(tmpdir);
                emit(
                    &mut on_progress,
                    LogarchiveDecodeProgress {
                        phase: "done",
                        detail: Some(format!(
                            "Unified-log decode complete · {} events",
                            events.len()
                        )),
                        max_lines: Some(max_lines),
                        files_materialized: Some(files_materialized),
                        events_decoded: Some(events.len()),
                        ..Default::default()
                    },
                );
                (
                    json!({
                        "status": "success",
                        "tool": "macos-unifiedlogs",
                        "event_count": events.len(),
                        "max_lines": max_lines,
                    }),
                    events,
                )
            }
            Err(reason) => {
                drop(tmpdir);
                emit(
                    &mut on_progress,
                    LogarchiveDecodeProgress {
                        phase: "failed",
                        detail: Some(reason.clone()),
                        max_lines: Some(max_lines),
                        files_materialized: Some(files_materialized),
                        ..Default::default()
                    },
                );
                (
                    json!({
                        "status": "failed",
                        "tool": "macos-unifiedlogs",
                        "reason": reason,
                        "max_lines": max_lines,
                    }),
                    Vec::new(),
                )
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn decode_inner(
    _archive: &SysdiagnoseArchive,
    max_lines: usize,
    mut on_progress: Option<&mut dyn FnMut(LogarchiveDecodeProgress)>,
) -> (Value, Vec<Value>) {
    if let Some(cb) = on_progress.as_mut() {
        cb(LogarchiveDecodeProgress {
            phase: "skipped",
            detail: Some("unified log decode requires a native host filesystem".into()),
            max_lines: Some(max_lines),
            ..Default::default()
        });
    }
    (
        json!({
            "status": "skipped",
            "reason": "unified log decode requires a native host filesystem (not available in WASM)",
            "max_lines": max_lines,
        }),
        Vec::new(),
    )
}

/// Decode unified logs; returns metadata (no embedded `events`) and event rows separately.
pub fn decode_logarchive_events(archive: &SysdiagnoseArchive) -> (Value, Vec<Value>) {
    decode_logarchive_events_with_limit(archive, default_logarchive_decode_max_lines())
}

/// Decode unified logs with an explicit line cap.
///
/// `max_lines == 0` means no cap (decode until the archive is exhausted).
pub fn decode_logarchive_events_with_limit(
    archive: &SysdiagnoseArchive,
    max_lines: usize,
) -> (Value, Vec<Value>) {
    decode_logarchive_events_with_limit_and_progress(archive, max_lines, None)
}

/// Decode with optional live progress (materialize + per-tracev3 updates).
pub fn decode_logarchive_events_with_limit_and_progress(
    archive: &SysdiagnoseArchive,
    max_lines: usize,
    on_progress: Option<&mut dyn FnMut(LogarchiveDecodeProgress)>,
) -> (Value, Vec<Value>) {
    use crate::parsers::parse_options::clamp_logarchive_decode_max_lines;
    let limit = clamp_logarchive_decode_max_lines(max_lines);
    decode_inner(archive, limit, on_progress)
}

/// Attempt unified-log decode (metadata only).
pub fn try_decode(archive: &SysdiagnoseArchive) -> Value {
    decode_logarchive_events(archive).0
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn materialize_lists_logarchive_files() {
        let mut m = HashMap::new();
        m.insert(
            "system_logs.logarchive/Info.plist".into(),
            Arc::from(b"plist".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let (_tmp, path) = materialize_logarchive(&arch).unwrap();
        assert!(path.join("Info.plist").is_file());
    }
}
