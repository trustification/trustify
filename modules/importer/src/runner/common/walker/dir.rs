use std::path::{Path, PathBuf};

pub trait WorkingDirectory {
    type Instance: AsRef<Path>;
    type Error: std::error::Error + Send + Sync;

    fn create(&self) -> Result<Self::Instance, Self::Error>;
}

/// Plain [`PathBuf`].
///
/// Will be created but not cleaned up.
impl WorkingDirectory for PathBuf {
    type Instance = PathBuf;
    type Error = std::io::Error;

    fn create(&self) -> Result<Self::Instance, Self::Error> {
        std::fs::create_dir_all(self)?;
        Ok(self.clone())
    }
}

/// Simple implementation based on [`tempfile::TempDir`].
///
/// Will be cleaned up when dropped.
impl WorkingDirectory for () {
    type Instance = tempfile::TempDir;
    type Error = std::io::Error;

    fn create(&self) -> Result<Self::Instance, Self::Error> {
        tempfile::TempDir::new()
    }
}
