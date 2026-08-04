//! Decode materialized `*.logarchive` directories with Mandiant macos-unifiedlogs.

use std::path::Path;

use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use macos_unifiedlogs::filesystem::LogarchiveProvider;
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{build_log, collect_timesync};
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};

/// One unified-log row, ready for the parent crate to map into SAF-style events.
#[derive(Debug, Clone)]
pub struct UnifiedLogEvent {
    pub datetime: DateTime<FixedOffset>,
    pub message: String,
    pub subsystem: String,
    pub category: String,
    pub process: String,
    pub thread_id: u64,
    pub event_type: String,
    pub timestamp: String,
    pub pid: u64,
    pub library: String,
    pub evidence: String,
}

/// Parse an RFC3339/Apollo-style timestamp, or derive from the row's nanosecond time field.
pub fn datetime_from_log_row(row: &LogData) -> Option<DateTime<FixedOffset>> {
    if !row.timestamp.is_empty() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&row.timestamp) {
            return Some(dt);
        }
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&row.timestamp, "%Y-%m-%d %H:%M:%S%.f %z")
        {
            return Some(dt.and_utc().fixed_offset());
        }
    }
    Utc.timestamp_nanos(row.time as i64)
        .with_timezone(&FixedOffset::east_opt(0)?)
        .into()
}

fn log_data_to_event(row: &LogData) -> Option<UnifiedLogEvent> {
    let datetime = datetime_from_log_row(row)?;
    let message = if row.message.is_empty() {
        row.raw_message.clone()
    } else {
        row.message.clone()
    };
    Some(UnifiedLogEvent {
        datetime,
        message,
        subsystem: row.subsystem.clone(),
        category: row.category.clone(),
        process: row.process.clone(),
        thread_id: row.thread_id,
        event_type: format!("{:?}", row.event_type),
        timestamp: row.timestamp.clone(),
        pid: row.pid,
        library: row.library.clone(),
        evidence: row.evidence.clone(),
    })
}

/// Decode unified logs from a materialized logarchive directory on disk.
///
/// When `max_lines` caps the decode, **newest** Persist / LiveData files are read
/// first and each opened file is fully decoded before truncating to the **newest**
/// `max_lines` by timestamp. Stopping mid-file after N rows would keep the oldest
/// lines inside a large Persist segment (boot noise) and drop afternoon unlock/PIN
/// activity.
pub fn decode_logarchive_dir(
    archive_path: &Path,
    max_lines: usize,
) -> Result<Vec<UnifiedLogEvent>, String> {
    decode_logarchive_dir_with_progress(archive_path, max_lines, None)
}

/// Same as [`decode_logarchive_dir`], with optional progress callbacks.
///
/// `on_progress` receives `(events_decoded, current_tracev3_path, tracev3_files_seen)`.
pub fn decode_logarchive_dir_with_progress(
    archive_path: &Path,
    max_lines: usize,
    mut on_progress: Option<&mut dyn FnMut(usize, &str, usize)>,
) -> Result<Vec<UnifiedLogEvent>, String> {
    let mut provider = LogarchiveProvider::new(archive_path);
    let timesync_data =
        collect_timesync(&provider).map_err(|e| format!("collect_timesync failed: {e:?}"))?;

    let mut events = Vec::new();
    let mut oversize_strings = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
        evidence: String::new(),
    };
    let mut missing_data = Vec::new();
    let mut tracev3_seen = 0usize;
    let mut last_report = std::time::Instant::now();
    let capped = max_lines > 0;

    let report = |cb: &mut Option<&mut dyn FnMut(usize, &str, usize)>,
                  events_len: usize,
                  path: &str,
                  files: usize,
                  force: bool,
                  last: &mut std::time::Instant| {
        let Some(cb) = cb else {
            return;
        };
        if force || last.elapsed() >= std::time::Duration::from_millis(400) {
            cb(events_len, path, files);
            *last = std::time::Instant::now();
        }
    };

    // Collect paths first so we can prefer recent Persist/LiveData over older Special.
    let mut sources: Vec<_> = provider.tracev3_files().collect();
    sources.sort_by(|a, b| {
        tracev3_decode_priority(a.source_path()).cmp(&tracev3_decode_priority(b.source_path()))
    });

    for mut source in sources {
        // Newest-first: once we already hold a full newest-N window, older files
        // cannot contribute anything newer.
        if capped && events.len() >= max_lines {
            break;
        }
        let path = source.source_path().to_string();
        if Path::new(&path)
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.starts_with("._"))
        {
            continue;
        }

        tracev3_seen += 1;
        report(
            &mut on_progress,
            events.len(),
            &path,
            tracev3_seen,
            true,
            &mut last_report,
        );

        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut source.reader(), &mut buf)
            .map_err(|e| format!("read tracev3 {path}: {e}"))?;

        let log_iterator = UnifiedLogIterator {
            data: buf,
            header: Vec::new(),
            evidence: path.clone(),
        };

        // Fully decode this file — Persist segments are chronological from the
        // start, so an early max_lines break would keep morning and drop afternoon.
        for mut chunk in log_iterator {
            chunk.oversize.append(&mut oversize_strings.oversize);
            let (results, missing_logs) = build_log(&chunk, &mut provider, &timesync_data, true);
            oversize_strings.oversize = chunk.oversize;

            for row in results {
                if let Some(ev) = log_data_to_event(&row) {
                    events.push(ev);
                }
            }

            report(
                &mut on_progress,
                events.len(),
                &path,
                tracev3_seen,
                false,
                &mut last_report,
            );

            if !missing_logs.catalog_data.is_empty()
                || !missing_logs.header.is_empty()
                || !missing_logs.oversize.is_empty()
            {
                // Bound leftover catalog work — unbounded growth was a multi‑GB RAM sink.
                if missing_data.len() < 256 {
                    missing_data.push(missing_logs);
                }
            }
        }

        if capped {
            retain_newest_events(&mut events, max_lines);
        }
    }

    for mut leftover in missing_data {
        if capped && events.len() >= max_lines {
            break;
        }
        leftover.oversize = oversize_strings.oversize.clone();
        let (results, _) = build_log(&leftover, &mut provider, &timesync_data, false);
        for row in results {
            if let Some(ev) = log_data_to_event(&row) {
                events.push(ev);
            }
        }
        if capped {
            retain_newest_events(&mut events, max_lines);
        }
        report(
            &mut on_progress,
            events.len(),
            "(leftover)",
            tracev3_seen,
            false,
            &mut last_report,
        );
    }

    report(
        &mut on_progress,
        events.len(),
        "",
        tracev3_seen,
        true,
        &mut last_report,
    );

    // Keep chronological order for consumers (we may have read LiveData before Persist).
    events.sort_by(|a, b| a.datetime.cmp(&b.datetime));
    if capped {
        retain_newest_events(&mut events, max_lines);
    }

    Ok(events)
}

/// Keep the newest `max_lines` events by timestamp (assumes/ensures chrono sort).
fn retain_newest_events(events: &mut Vec<UnifiedLogEvent>, max_lines: usize) {
    if max_lines == 0 || events.len() <= max_lines {
        return;
    }
    events.sort_by(|a, b| a.datetime.cmp(&b.datetime));
    let skip = events.len() - max_lines;
    events.drain(0..skip);
}

/// Lower tuple = decoded earlier when capped. Prefer LiveData + newest Persist.
fn tracev3_decode_priority(path: &str) -> (u8, std::cmp::Reverse<String>) {
    let normalized = path.replace('\\', "/");
    let file = normalized
        .rsplit('/')
        .next()
        .unwrap_or(normalized.as_str())
        .to_string();
    if file.contains("LiveData") {
        return (0, std::cmp::Reverse(file));
    }
    if normalized.contains("/Persist/") {
        // Higher hex id (1da6 > 1da0) ≈ newer segment.
        return (1, std::cmp::Reverse(file));
    }
    if normalized.contains("/Special/") {
        return (2, std::cmp::Reverse(file));
    }
    // Signpost / other — lowest priority for unlock forensics.
    (3, std::cmp::Reverse(file))
}

/// True when the logarchive directory contains at least one tracev3 file.
pub fn logarchive_has_tracev3(archive_path: &Path) -> bool {
    let provider = LogarchiveProvider::new(archive_path);
    provider.tracev3_files().next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use macos_unifiedlogs::unified_log::{EventType, LogType};

    #[test]
    fn log_data_to_event_maps_fields() {
        let row = LogData {
            subsystem: "com.apple.test".into(),
            thread_id: 1,
            pid: 42,
            euid: 501,
            library: "lib".into(),
            library_uuid: "uuid".into(),
            activity_id: 0,
            parent_activity_id: 0,
            time: 1_700_000_000_000_000_000.0,
            category: "default".into(),
            event_type: EventType::Log,
            log_type: LogType::Default,
            process: "testproc".into(),
            process_uuid: "puuid".into(),
            message: "hello unified".into(),
            raw_message: String::new(),
            boot_uuid: String::new(),
            timezone_name: "UTC".into(),
            message_entries: Vec::new(),
            timestamp: "2023-11-14T22:13:20Z".into(),
            message_flags: Vec::new(),
            evidence: "/tmp/x.tracev3".into(),
        };
        let ev = log_data_to_event(&row).unwrap();
        assert_eq!(ev.message, "hello unified");
        assert_eq!(ev.process, "testproc");
        assert_eq!(ev.subsystem, "com.apple.test");
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use std::path::Path;

    /// Set `SYSDIAGNOSE_LOGARCHIVE_FIXTURE` to a materialized `.logarchive` directory.
    #[test]
    #[ignore = "requires SYSDIAGNOSE_LOGARCHIVE_FIXTURE pointing at a logarchive tree"]
    fn decode_fixture_logarchive_dir() {
        let Some(path) = std::env::var("SYSDIAGNOSE_LOGARCHIVE_FIXTURE").ok() else {
            eprintln!("skip: SYSDIAGNOSE_LOGARCHIVE_FIXTURE not set");
            return;
        };
        let path = Path::new(&path);
        assert!(path.is_dir(), "fixture must be a directory");
        assert!(logarchive_has_tracev3(path));
        let events = decode_logarchive_dir(path, 100).expect("decode");
        assert!(!events.is_empty(), "expected decoded log lines");
    }
}
