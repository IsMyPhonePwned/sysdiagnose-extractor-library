//! Runtime options for parsers (CLI / library API).

const DEFAULT_LOGARCHIVE_DECODE_MAX_LINES: usize = 2_500;

/// Hard ceiling for "uncapped" / forensic unified-log decode (never `usize::MAX`).
/// Prevents multi‑tens‑of‑GB `Vec` growth while still covering large investigations.
pub const LOGARCHIVE_FORENSIC_MAX_LINES: usize = 250_000;

/// Options passed when running parsers (subset of parsers honor these).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOptions {
    /// When true, [`crate::parsers::IoserviceParser`] returns the full IOReg `tree`
    /// instead of the default compact preview.
    pub ioservice_full_tree: bool,
    /// Max unified-log lines to decode from `system_logs.logarchive/` per run.
    /// Values above [`LOGARCHIVE_FORENSIC_MAX_LINES`] are clamped.
    pub logarchive_decode_max_lines: usize,
    /// When true, [`crate::parsers::LogarchiveParser`] only builds inventory (no decode).
    /// Use when the host will decode once after other parsers finish (avoids double decode).
    pub logarchive_inventory_only: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            ioservice_full_tree: false,
            logarchive_decode_max_lines: logarchive_decode_max_lines_from_env(),
            logarchive_inventory_only: false,
        }
    }
}

pub fn default_logarchive_decode_max_lines() -> usize {
    DEFAULT_LOGARCHIVE_DECODE_MAX_LINES
}

/// Clamp a requested decode line cap (0 / huge → forensic ceiling).
pub fn clamp_logarchive_decode_max_lines(max_lines: usize) -> usize {
    if max_lines == 0 || max_lines > LOGARCHIVE_FORENSIC_MAX_LINES {
        LOGARCHIVE_FORENSIC_MAX_LINES
    } else {
        max_lines
    }
}

fn logarchive_decode_max_lines_from_env() -> usize {
    std::env::var("SYSDIAGNOSE_LOGARCHIVE_DECODE_MAX_LINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(clamp_logarchive_decode_max_lines)
        .unwrap_or(DEFAULT_LOGARCHIVE_DECODE_MAX_LINES)
}
