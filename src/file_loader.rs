//! Load sysdiagnose archives from disk (`.tar.gz` or `.tar`), mirroring the role of
//! `file_loader` in `bugreport-extractor-library`.

use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use tracing::info;

use crate::archive::{ArchiveOptions, SysdiagnoseArchive};

/// Opens a sysdiagnose tarball with default limits ([`ArchiveOptions::default`]).
pub fn load_sysdiagnose_file<P: AsRef<Path>>(
    file_path: P,
) -> Result<Arc<SysdiagnoseArchive>, Box<dyn Error + Send + Sync>> {
    load_sysdiagnose_file_with_options(file_path, ArchiveOptions::default())
}

/// Opens a tarball with custom per-member size limits.
pub fn load_sysdiagnose_file_with_options<P: AsRef<Path>>(
    file_path: P,
    options: ArchiveOptions,
) -> Result<Arc<SysdiagnoseArchive>, Box<dyn Error + Send + Sync>> {
    let file_path = file_path.as_ref();
    let arch = SysdiagnoseArchive::open_path_with_options(file_path, options)?;
    info!(
        path = %file_path.display(),
        files = arch.len(),
        bundle = ?arch.bundle_dir_name(),
        "Loaded sysdiagnose archive"
    );
    Ok(Arc::new(arch))
}
