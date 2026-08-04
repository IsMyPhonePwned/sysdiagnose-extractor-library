//! Caps for the [`plists`](crate::parsers::PlistsParser) parser (overridable via environment).

/// Default maximum plist files to parse (0 = unlimited).
pub const DEFAULT_MAX_PLIST_FILES: usize = 600;

/// Default per-file byte cap (0 = unlimited).
pub const DEFAULT_MAX_PLIST_EACH_BYTES: usize = 4 * 1024 * 1024;

/// Runtime caps for `plists` (from env or defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlistsCaps {
    /// Maximum number of plist paths to parse. `0` = no limit.
    pub max_files: usize,
    /// Skip plists larger than this many bytes. `0` = no limit.
    pub max_each_bytes: usize,
}

impl Default for PlistsCaps {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_PLIST_FILES,
            max_each_bytes: DEFAULT_MAX_PLIST_EACH_BYTES,
        }
    }
}

impl PlistsCaps {
    /// Read `SYSDIAGNOSE_PLISTS_MAX_FILES` and `SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES`.
    pub fn from_env() -> Self {
        Self {
            max_files: env_usize("SYSDIAGNOSE_PLISTS_MAX_FILES")
                .unwrap_or(DEFAULT_MAX_PLIST_FILES),
            max_each_bytes: env_usize("SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES")
                .unwrap_or(DEFAULT_MAX_PLIST_EACH_BYTES),
        }
    }
}

fn env_usize(name: &str) -> Option<usize> {
    let v = std::env::var(name).ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    v.parse().ok()
}
