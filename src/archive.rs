use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, FixedOffset};
use flate2::read::GzDecoder;
use regex::Regex;
use tracing::warn;

use crate::error::ArchiveError;

/// Default cap per tar member (skip larger files to limit RAM).
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Default cap for nested `sysdiagnose_*.tar.gz` members (CSIRC crash+sysdiagnose packs).
pub const DEFAULT_MAX_NESTED_SYSDIAGNOSE_BYTES: u64 = 512 * 1024 * 1024;

const LOGARCHIVE_PREFIX: &str = "system_logs.logarchive/";

/// Members under logarchive larger than this (or `*.tracev3`) are spilled to disk, not RAM.
const LOGARCHIVE_SPILL_MIN_BYTES: u64 = 1024 * 1024;

/// Options for loading a sysdiagnose tarball.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveOptions {
    /// Maximum uncompressed size per regular file; larger members are skipped.
    pub max_entry_bytes: u64,
    /// Max size for nested `sysdiagnose_*.tar.gz` / `.tgz` members that are expanded in place.
    pub max_nested_sysdiagnose_bytes: u64,
    /// When true, expand nested Apple `sysdiagnose_*.tar.gz` members into this archive's file map.
    pub expand_nested_sysdiagnose: bool,
    /// Spill heavy `system_logs.logarchive/` members (`.tracev3` / >1 MiB) to a temp dir.
    pub spill_logarchive_heavy: bool,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
            max_nested_sysdiagnose_bytes: DEFAULT_MAX_NESTED_SYSDIAGNOSE_BYTES,
            expand_nested_sysdiagnose: true,
            // Native default: avoid multi‑GB Persist/*.tracev3 copies in the HashMap.
            spill_logarchive_heavy: cfg!(not(target_arch = "wasm32")),
        }
    }
}

fn should_spill_logarchive_member(rel: &str, size: u64) -> bool {
    if !rel.starts_with(LOGARCHIVE_PREFIX) {
        return false;
    }
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with(".tracev3") || size >= LOGARCHIVE_SPILL_MIN_BYTES
}

/// True for nested full-sysdiagnose tarballs (e.g. under CrashReporter/DiagnosticLogs).
fn is_nested_sysdiagnose_member(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let lower = name.to_ascii_lowercase();
    lower.starts_with("sysdiagnose_")
        && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".tar.xz"))
}

fn is_gzip_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// XZ stream magic (`FD 37 7A 58 5A 00`).
fn is_xz_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 6
        && bytes[0] == 0xfd
        && bytes[1] == 0x37
        && bytes[2] == 0x7a
        && bytes[3] == 0x58
        && bytes[4] == 0x5a
        && bytes[5] == 0x00
}

#[cfg(target_arch = "wasm32")]
fn decompress_xz(data: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let _ = data;
    Err(ArchiveError::XzUnsupported)
}

/// Parses acquisition time from bundle folder names such as
/// `sysdiagnose_2026.04.07_15-01-20+0200_iPhone-OS_iPhone_23D127`.
pub fn parse_bundle_acquisition(dir_name: &str) -> Option<DateTime<FixedOffset>> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^sysdiagnose_(\d{4}\.\d{2}\.\d{2}_\d{2}-\d{2}-\d{2})([+-]\d{4})")
            .expect("regex")
    });
    let cap = re.captures(dir_name)?;
    let dt = cap.get(1)?.as_str();
    let tz = cap.get(2)?.as_str();
    let combined = format!("{dt}{tz}");
    DateTime::parse_from_str(&combined, "%Y.%m.%d_%H-%M-%S%z").ok()
}

/// Normalizes tar paths: strips the top-level sysdiagnose bundle directory and drops
/// AppleDouble (`._*`) entries. Returns `(bundle_dir_name, relative_path)`.
fn normalize_member_path(path: &str) -> Option<(String, String)> {
    let path = path.replace('\\', "/");
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    if parts.iter().any(|p| p.starts_with("._")) {
        return None;
    }
    let bundle = parts[0].to_string();
    let rel = parts[1..].join("/");
    Some((bundle, rel))
}

/// In-memory view of a sysdiagnose `.tar`, `.tar.gz`, or `.tar.xz` archive (same layout as SAF case `data/`).
///
/// Also accepts CSIRC-style supplemental crash dumps whose members begin with
/// `private/var/.../CrashReporter/` (no `sysdiagnose_*` top folder). When such a pack embeds a
/// nested `sysdiagnose_*.tar.gz` (often under `CrashReporter/DiagnosticLogs/sysdiagnose/`), that
/// archive is expanded into the same file map (outer CrashReporter `.ips` paths win on conflict).
#[derive(Debug)]
pub struct SysdiagnoseArchive {
    /// Paths relative to the bundle root (e.g. `ps.txt`, `logs/SystemVersion/SystemVersion.plist`).
    files: HashMap<String, Arc<[u8]>>,
    /// First top-level directory name from the archive (often encodes acquisition time).
    bundle_dir_name: Option<String>,
    /// Parsed from [`Self::bundle_dir_name`] when it matches the Apple naming pattern.
    acquisition: Option<DateTime<FixedOffset>>,
    /// Temp dir holding spilled heavy logarchive members (native only).
    #[cfg(not(target_arch = "wasm32"))]
    logarchive_spill: Option<tempfile::TempDir>,
    /// `(archive-relative path, size)` for members written under [`Self::logarchive_spill`].
    #[cfg(not(target_arch = "wasm32"))]
    logarchive_spilled: Vec<(String, u64)>,
}

impl SysdiagnoseArchive {
    /// Load from raw bytes with default limits ([`ArchiveOptions::default`]).
    pub fn from_bytes(data: &[u8]) -> Result<Self, ArchiveError> {
        Self::from_bytes_with_options(data, ArchiveOptions::default())
    }

    pub fn from_bytes_with_options(
        data: &[u8],
        options: ArchiveOptions,
    ) -> Result<Self, ArchiveError> {
        // Stream decompress → tar so we never hold a full uncompressed tar copy
        // alongside the file map (previous path buffered the whole decompress Vec).
        if is_gzip_prefix(data) {
            let decoder = GzDecoder::new(Cursor::new(data));
            return Self::from_tar_reader_with_options(decoder, options);
        }
        if is_xz_prefix(data) {
            #[cfg(not(target_arch = "wasm32"))]
            {
                use xz2::read::XzDecoder;
                let decoder = XzDecoder::new(Cursor::new(data));
                return Self::from_tar_reader_with_options(decoder, options);
            }
            #[cfg(target_arch = "wasm32")]
            {
                let decompressed = decompress_xz(data)?;
                return Self::from_tar_bytes_with_options(&decompressed, options);
            }
        }
        Self::from_tar_bytes_with_options(data, options)
    }

    /// Memory-map a file and load it (handles `.tar.gz`, `.tar.xz`, and `.tar`).
    pub fn open_path<P: AsRef<Path>>(path: P) -> Result<Self, ArchiveError> {
        Self::open_path_with_options(path, ArchiveOptions::default())
    }

    pub fn open_path_with_options<P: AsRef<Path>>(
        path: P,
        options: ArchiveOptions,
    ) -> Result<Self, ArchiveError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(ArchiveError::NotAFile(path.to_path_buf()));
        }
        let file = File::open(path)?;
        // SAFETY: file is not mutated while mapped.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Self::from_bytes_with_options(&mmap[..], options)
    }

    fn from_tar_bytes_with_options(
        tar_data: &[u8],
        options: ArchiveOptions,
    ) -> Result<Self, ArchiveError> {
        Self::from_tar_reader_with_options(Cursor::new(tar_data), options)
    }

    fn from_tar_reader_with_options<R: Read>(
        reader: R,
        options: ArchiveOptions,
    ) -> Result<Self, ArchiveError> {
        let mut archive = tar::Archive::new(reader);
        let mut files = HashMap::new();
        let mut bundle_dir_name: Option<String> = None;
        let mut nested_to_merge: Vec<Self> = Vec::new();
        #[cfg(not(target_arch = "wasm32"))]
        let mut logarchive_spill: Option<tempfile::TempDir> = None;
        #[cfg(not(target_arch = "wasm32"))]
        let mut logarchive_spilled: Vec<(String, u64)> = Vec::new();

        for entry in archive
            .entries()
            .map_err(|e| ArchiveError::Tar(e.to_string()))?
        {
            let mut entry = entry.map_err(|e| ArchiveError::Tar(e.to_string()))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|e| ArchiveError::Tar(e.to_string()))?
                .to_string_lossy()
                .into_owned();
            let Some((bundle, rel)) = normalize_member_path(&path) else {
                continue;
            };
            if bundle_dir_name.is_none() {
                bundle_dir_name = Some(bundle.clone());
            }
            let nested = options.expand_nested_sysdiagnose && is_nested_sysdiagnose_member(&rel);
            let size_limit = if nested {
                options.max_nested_sysdiagnose_bytes
            } else {
                options.max_entry_bytes
            };
            let size = entry.size();
            if size > size_limit {
                warn!(
                    path = %rel,
                    size,
                    limit = size_limit,
                    "Skipping oversized archive member"
                );
                continue;
            }

            // Stream heavy unified-log chunks straight to disk (no multi‑GB Vec in RAM).
            #[cfg(not(target_arch = "wasm32"))]
            if options.spill_logarchive_heavy && !nested && should_spill_logarchive_member(&rel, size)
            {
                let spill = match &logarchive_spill {
                    Some(t) => t,
                    None => {
                        let t = tempfile::Builder::new()
                            .prefix("sysdiagnose_logarchive_spill_")
                            .tempdir()
                            .map_err(|e| ArchiveError::Tar(e.to_string()))?;
                        logarchive_spill = Some(t);
                        logarchive_spill.as_ref().expect("just inserted")
                    }
                };
                let rel_under = &rel[LOGARCHIVE_PREFIX.len()..];
                let dest = spill.path().join(rel_under);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| ArchiveError::Tar(e.to_string()))?;
                }
                let mut out = File::create(&dest).map_err(|e| ArchiveError::Tar(e.to_string()))?;
                std::io::copy(&mut entry, &mut out).map_err(|e| ArchiveError::Tar(e.to_string()))?;
                logarchive_spilled.push((rel, size));
                continue;
            }

            let mut buf = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut buf)
                .map_err(|e| ArchiveError::Tar(e.to_string()))?;

            if nested {
                let mut nested_opts = options;
                // Avoid recursive expansion of archives nested inside the nested dump.
                nested_opts.expand_nested_sysdiagnose = false;
                match Self::from_bytes_with_options(&buf, nested_opts) {
                    Ok(inner) => {
                        tracing::info!(
                            path = %rel,
                            nested_files = inner.len(),
                            "Expanded nested sysdiagnose archive"
                        );
                        nested_to_merge.push(inner);
                    }
                    Err(err) => {
                        warn!(
                            path = %rel,
                            error = %err,
                            "Failed to expand nested sysdiagnose archive; skipping member"
                        );
                    }
                }
                continue;
            }

            files.insert(rel, Arc::from(buf.into_boxed_slice()));
        }

        for nested in nested_to_merge {
            if nested
                .bundle_dir_name
                .as_deref()
                .and_then(parse_bundle_acquisition)
                .is_some()
            {
                if bundle_dir_name
                    .as_deref()
                    .and_then(parse_bundle_acquisition)
                    .is_none()
                {
                    bundle_dir_name = nested.bundle_dir_name.clone();
                }
            }
            for (path, bytes) in nested.files {
                // Outer members (e.g. CrashReporter .ips) win over duplicates in the nested dump.
                files.entry(path).or_insert(bytes);
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                // Prefer outer spill; absorb nested spill only when we have none yet.
                if logarchive_spill.is_none() {
                    if let Some(spill) = nested.logarchive_spill {
                        logarchive_spill = Some(spill);
                        logarchive_spilled = nested.logarchive_spilled;
                    }
                }
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        let has_spilled = !logarchive_spilled.is_empty();
        #[cfg(target_arch = "wasm32")]
        let has_spilled = false;

        if files.is_empty() && !has_spilled {
            return Err(ArchiveError::EmptyArchive);
        }

        let acquisition = bundle_dir_name
            .as_deref()
            .and_then(parse_bundle_acquisition);

        #[cfg(not(target_arch = "wasm32"))]
        if !logarchive_spilled.is_empty() {
            tracing::info!(
                spilled = logarchive_spilled.len(),
                "Spilled heavy logarchive members to disk (not held in RAM)"
            );
        }

        Ok(Self {
            files,
            bundle_dir_name,
            acquisition,
            #[cfg(not(target_arch = "wasm32"))]
            logarchive_spill,
            #[cfg(not(target_arch = "wasm32"))]
            logarchive_spilled,
        })
    }

    pub fn get(&self, relative_path: &str) -> Option<&[u8]> {
        self.files.get(relative_path).map(|arc| arc.as_ref())
    }

    /// First path matching `suffix` (e.g. `"SystemVersion.plist"` when multiple copies exist).
    pub fn find_suffix(&self, suffix: &str) -> Option<(&str, &[u8])> {
        self.files
            .iter()
            .find(|(k, _)| k.ends_with(suffix))
            .map(|(k, v)| (k.as_str(), v.as_ref()))
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// Iterate `(relative_path, file_bytes)` sorted by path (for deterministic SAF-style output).
    pub fn iter_files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        let mut v: Vec<(&str, &[u8])> = self
            .files
            .iter()
            .map(|(k, a)| (k.as_str(), a.as_ref()))
            .collect();
        v.sort_by_key(|(p, _)| *p);
        v.into_iter()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Drop members under `prefix` from the in-memory map (frees RAM after materialize/decode).
    pub fn purge_prefix(&mut self, prefix: &str) -> usize {
        let before = self.files.len();
        self.files.retain(|k, _| !k.starts_with(prefix));
        let mut removed = before.saturating_sub(self.files.len());
        #[cfg(not(target_arch = "wasm32"))]
        if LOGARCHIVE_PREFIX.starts_with(prefix) || prefix.starts_with(LOGARCHIVE_PREFIX) || prefix == "system_logs.logarchive" {
            removed += self.logarchive_spilled.len();
            self.logarchive_spilled.clear();
            self.logarchive_spill = None;
        }
        removed
    }

    /// Spilled heavy logarchive members `(relative path, size)` — not present in [`Self::get`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn logarchive_spilled_entries(&self) -> &[(String, u64)] {
        &self.logarchive_spilled
    }

    /// Root of the on-disk spill for heavy logarchive members, when any were spilled.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn logarchive_spill_dir(&self) -> Option<&Path> {
        self.logarchive_spill.as_ref().map(|t| t.path())
    }

    /// Absolute path on disk for a spilled archive-relative path, if present.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn spilled_logarchive_abs(&self, relative_path: &str) -> Option<PathBuf> {
        let spill = self.logarchive_spill.as_ref()?;
        let under = relative_path.strip_prefix(LOGARCHIVE_PREFIX)?;
        let dest = spill.path().join(under);
        dest.is_file().then_some(dest)
    }

    /// Top-level folder inside the tarball (e.g. `sysdiagnose_2026..._iPhone_23D127`).
    pub fn bundle_dir_name(&self) -> Option<&str> {
        self.bundle_dir_name.as_deref()
    }

    /// Wall-clock time parsed from the bundle folder name, when available.
    pub fn acquisition(&self) -> Option<DateTime<FixedOffset>> {
        self.acquisition
    }
}

impl SysdiagnoseArchive {
    /// Build an in-memory archive (no tarball). For tests and tools that inject path→bytes maps.
    #[doc(hidden)]
    pub fn from_files_for_test(files: HashMap<String, Arc<[u8]>>) -> Self {
        Self {
            files,
            bundle_dir_name: None,
            acquisition: None,
            #[cfg(not(target_arch = "wasm32"))]
            logarchive_spill: None,
            #[cfg(not(target_arch = "wasm32"))]
            logarchive_spilled: Vec::new(),
        }
    }

    #[doc(hidden)]
    pub fn from_files_for_test_with_bundle(
        files: HashMap<String, Arc<[u8]>>,
        bundle_dir_name: Option<String>,
    ) -> Self {
        let acquisition = bundle_dir_name
            .as_deref()
            .and_then(parse_bundle_acquisition);
        Self {
            files,
            bundle_dir_name,
            acquisition,
            #[cfg(not(target_arch = "wasm32"))]
            logarchive_spill: None,
            #[cfg(not(target_arch = "wasm32"))]
            logarchive_spilled: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    fn make_sample_tar_gz() -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            let root = "sysdiagnose_test_iPhone/";
            let mut header = tar::Header::new_gnu();
            let data = b"hello";
            header.set_path(format!("{root}ps.txt")).unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn loads_gzipped_tar() {
        let gz = make_sample_tar_gz();
        let arch = SysdiagnoseArchive::from_bytes(&gz).unwrap();
        assert_eq!(arch.get("ps.txt").unwrap(), b"hello");
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn make_sample_tar_xz() -> Vec<u8> {
        use xz2::write::XzEncoder;
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            let root = "private/";
            let mut header = tar::Header::new_gnu();
            let data = b"{\"app_name\":\"Test\"}\n{}";
            header
                .set_path(format!(
                    "{root}var/mobile/Library/Logs/CrashReporter/TestApp-2025-04-07-080618.ips"
                ))
                .unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut xz = XzEncoder::new(Vec::new(), 1);
        xz.write_all(&tar_buf).unwrap();
        xz.finish().unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn loads_xz_tar_with_crashreporter_layout() {
        let xz = make_sample_tar_xz();
        assert!(is_xz_prefix(&xz));
        let arch = SysdiagnoseArchive::from_bytes(&xz).unwrap();
        assert!(arch
            .get("var/mobile/Library/Logs/CrashReporter/TestApp-2025-04-07-080618.ips")
            .is_some());
        assert_eq!(arch.bundle_dir_name(), Some("private"));
    }

    #[test]
    fn expands_nested_sysdiagnose_tar_gz() {
        let nested = make_sample_tar_gz();
        let mut outer_tar = Vec::new();
        {
            let mut tar = Builder::new(&mut outer_tar);
            let root = "private/";
            let ips = b"{\"app_name\":\"Outer\"}\n{}";
            let mut h1 = tar::Header::new_gnu();
            h1.set_path(format!(
                "{root}var/mobile/Library/Logs/CrashReporter/Outer-1.ips"
            ))
            .unwrap();
            h1.set_size(ips.len() as u64);
            h1.set_cksum();
            tar.append(&h1, &ips[..]).unwrap();

            let nested_name = format!("{root}DiagnosticLogs/sysdiagnose_nested.tar.gz");
            let mut h2 = tar::Header::new_gnu();
            h2.set_path(&nested_name).unwrap();
            h2.set_size(nested.len() as u64);
            h2.set_cksum();
            tar.append(&h2, &nested[..]).unwrap();
            tar.finish().unwrap();
        }

        let arch = SysdiagnoseArchive::from_bytes(&outer_tar).unwrap();
        assert!(arch
            .get("var/mobile/Library/Logs/CrashReporter/Outer-1.ips")
            .is_some());
        assert_eq!(arch.get("ps.txt").unwrap(), b"hello");
        // Nested blob itself is not kept as a member.
        assert!(arch.paths().all(|p| !p.ends_with(".tar.gz")));
    }

    #[test]
    fn parses_acquisition_from_bundle_name() {
        let s = "sysdiagnose_2026.04.07_15-01-20+0200_iPhone-OS_iPhone_23D127";
        let dt = parse_bundle_acquisition(s).unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M").to_string(), "2026-04-07 15:01");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn spills_heavy_tracev3_out_of_ram() {
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            let root = "sysdiagnose_test_iPhone/";
            let small = b"plist";
            let mut h1 = tar::Header::new_gnu();
            h1.set_path(format!("{root}system_logs.logarchive/Info.plist"))
                .unwrap();
            h1.set_size(small.len() as u64);
            h1.set_cksum();
            tar.append(&h1, &small[..]).unwrap();

            let heavy = vec![0u8; 64 * 1024];
            let mut h2 = tar::Header::new_gnu();
            h2.set_path(format!(
                "{root}system_logs.logarchive/Persist/0000000000000001.tracev3"
            ))
            .unwrap();
            h2.set_size(heavy.len() as u64);
            h2.set_cksum();
            tar.append(&h2, &heavy[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        let bytes = gz.finish().unwrap();

        let arch = SysdiagnoseArchive::from_bytes_with_options(
            &bytes,
            ArchiveOptions {
                spill_logarchive_heavy: true,
                max_entry_bytes: 128 * 1024 * 1024,
                ..ArchiveOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            arch.get("system_logs.logarchive/Info.plist").unwrap(),
            b"plist"
        );
        assert!(arch
            .get("system_logs.logarchive/Persist/0000000000000001.tracev3")
            .is_none());
        assert_eq!(arch.logarchive_spilled_entries().len(), 1);
        assert!(arch
            .spilled_logarchive_abs("system_logs.logarchive/Persist/0000000000000001.tracev3")
            .is_some());
    }
}
