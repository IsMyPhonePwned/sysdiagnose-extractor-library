use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid tar archive: {0}")]
    Tar(String),

    #[error("Archive has no sysdiagnose root folder with data files")]
    EmptyArchive,

    #[error("XZ / .tar.xz archives are not supported on this target")]
    XzUnsupported,

    #[error("Path is not a file: {0}")]
    NotAFile(PathBuf),
}
