use crate::server::common::walker::WorkingDirectory;
use anyhow::anyhow;
use std::borrow::Cow;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::{Debug, Display};
use std::path::{Path, PathBuf};
use tokio::task::JoinError;
use tracing::instrument;
use walkdir::{DirEntry, WalkDir};

#[cfg(not(feature = "git2"))]
mod cli;
#[cfg(all(test, not(feature = "git2")))]
pub(crate) use cli::test;

#[cfg(feature = "git2")]
mod git2;
#[cfg(all(test, feature = "git2"))]
pub(crate) use git2::test;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Continuation(Option<String>);

pub trait Handler: Send + 'static {
    type Error: Display + Debug;

    fn process(&mut self, path: &Path, relative_path: &Path) -> Result<(), Self::Error>;
}

impl Handler for () {
    type Error = Infallible;

    fn process(&mut self, _: &Path, _: &Path) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to await the task: {0}")]
    Join(#[from] JoinError),
    #[error("failed to create the working directory: {0}")]
    WorkingDir(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[cfg(feature = "git2")]
    #[error(transparent)]
    Git(#[from] ::git2::Error),
    #[cfg(not(feature = "git2"))]
    #[error(transparent)]
    Shell(#[from] xshell::Error),
    #[error("failed to walk files: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("critical processing error: {0}")]
    Processing(#[source] anyhow::Error),
    #[error("{0} is not a relative subdirectory of the repository")]
    Path(String),
}

pub struct GitWalker<H, T>
where
    T: WorkingDirectory + Send + 'static,
    H: Handler,
{
    /// The git source to clone from
    pub source: String,

    /// A path inside the cloned repository to start searching for files
    pub path: Option<String>,

    /// Continuation token
    pub continuation: Continuation,

    /// A working directory
    pub working_dir: T,

    /// The handler
    pub handler: H,
}

impl<H> GitWalker<H, ()>
where
    H: Handler,
{
    pub fn new(source: impl Into<String>, handler: H) -> Self {
        Self {
            source: source.into(),
            path: None,
            continuation: Default::default(),
            working_dir: (),
            handler,
        }
    }
}

impl<H, T> GitWalker<H, T>
where
    H: Handler,
    T: WorkingDirectory + Send + 'static,
{
    pub fn handler<U: Handler>(self, handler: U) -> GitWalker<U, T> {
        GitWalker {
            source: self.source,
            path: self.path,
            continuation: self.continuation,
            working_dir: self.working_dir,
            handler,
        }
    }

    /// Set a working directory.
    ///
    /// The data in this working directory will be re-used. However, it must be specific to the
    /// source used. It is not possible to re-use the same working-directory for multiple different
    /// sources.
    ///
    /// It may also be `()`, which uses a temporary working directory. However, this will result in
    /// the walker cloning the full repository with ever run, which might be quite expensive.
    pub fn working_dir<U: WorkingDirectory + Send + 'static>(
        self,
        working_dir: U,
    ) -> GitWalker<H, U> {
        GitWalker {
            source: self.source,
            path: self.path,
            continuation: self.continuation,
            working_dir,
            handler: self.handler,
        }
    }

    pub fn path(mut self, path: Option<impl Into<String>>) -> Self {
        self.path = path.map(|s| s.into());
        self
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: Continuation) -> Self {
        self.continuation = continuation;
        self
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<Continuation, Error> {
        tokio::task::spawn_blocking(move || self.run_sync()).await?
    }

    #[instrument(skip(self, changes), err)]
    fn walk(&mut self, path: &Path, changes: &Option<HashSet<PathBuf>>) -> Result<(), Error> {
        let mut base = Cow::Borrowed(path);
        if let Some(join_base) = &self.path {
            let new_path = path.join(join_base);

            log::debug!("  Base: {}", path.display());
            log::debug!("Target: {}", new_path.display());

            // ensure that self.path was a relative sub-directory of the repository
            let _ = new_path
                .strip_prefix(path)
                .map_err(|_| Error::Path(join_base.into()))?;

            base = new_path.into();
        }

        for entry in WalkDir::new(&base)
            .into_iter()
            .filter_entry(|entry| !is_hidden(entry))
        {
            let entry = entry?;

            log::trace!("Checking: {entry:?}");

            if !entry.file_type().is_file() {
                continue;
            }

            // the path in the filesystem
            let path = entry.path();
            // the path, relative to the base (plus repo) dir
            let path = path.strip_prefix(&base).unwrap_or(path);

            if let Some(changes) = changes {
                if !changes.contains(path) {
                    log::trace!("Skipping {}, as file did not change", path.display());
                    continue;
                }
            }

            self.handler
                .process(entry.path(), path)
                .map_err(|err| Error::Processing(anyhow!("{err}")))?;
        }

        Ok(())
    }
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}
