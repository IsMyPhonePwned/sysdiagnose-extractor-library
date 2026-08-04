use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::archive::SysdiagnoseArchive;

/// Build a matcher for SAF-style glob paths (forward slashes, `**` supported).
pub fn compile_globs(patterns: &[&str]) -> Result<GlobSet, globset::Error> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p)?);
    }
    b.build()
}

pub fn matching_files<'a>(
    archive: &'a SysdiagnoseArchive,
    set: &GlobSet,
) -> Vec<(&'a str, &'a [u8])> {
    let mut v: Vec<_> = archive
        .iter_files()
        .filter(|(p, _)| set.is_match(*p))
        .collect();
    v.sort_by_key(|(p, _)| *p);
    v
}

pub fn matching_files_patterns<'a>(
    archive: &'a SysdiagnoseArchive,
    patterns: &[&str],
) -> Result<Vec<(&'a str, &'a [u8])>, globset::Error> {
    let set = compile_globs(patterns)?;
    Ok(matching_files(archive, &set))
}
