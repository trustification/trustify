use git2::{
    build::RepoBuilder, ErrorClass, ErrorCode, FetchOptions, RemoteCallbacks, Repository, ResetType,
};
use osv::schema::Vulnerability;
use std::{
    borrow::Cow,
    collections::HashSet,
    io::BufReader,
    path::{Path, PathBuf},
};
use tokio::task::JoinError;
use tracing::instrument;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to await the task: {0}")]
    Join(#[from] JoinError),
    #[error("failed to create the working directory: {0}")]
    WorkingDir(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Git(#[from] git2::Error),
    #[error("failed to walk files: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("critical processing error: {0}")]
    Processing(#[source] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("critical error: {0}")]
    Critical(anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
}

pub trait WorkingDirectory {
    type Instance: AsRef<Path>;
    type Error: std::error::Error + Send + Sync;

    fn create(&self) -> Result<Self::Instance, Self::Error>;
}

impl WorkingDirectory for PathBuf {
    type Instance = PathBuf;
    type Error = std::io::Error;

    fn create(&self) -> Result<Self::Instance, Self::Error> {
        std::fs::create_dir_all(self)?;
        Ok(self.clone())
    }
}

impl WorkingDirectory for () {
    type Instance = tempfile::TempDir;
    type Error = std::io::Error;

    fn create(&self) -> Result<Self::Instance, Self::Error> {
        tempfile::TempDir::new()
    }
}

pub trait Callbacks {
    /// Handle an error while loading the file
    #[allow(unused)]
    fn loading_error(&mut self, path: PathBuf, message: String) {}

    /// Process the file.
    ///
    /// Any error returned will terminate the walk with a critical error.
    #[allow(unused)]
    fn process(&mut self, path: &Path, osv: Vulnerability) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

impl Callbacks for () {}

pub struct OsvWalker<C, T>
where
    C: Callbacks,
    T: WorkingDirectory + Send + 'static,
{
    /// The git source to clone from
    pub source: String,

    /// A path inside the cloned repository to start searching for files
    pub path: Option<String>,

    /// Continuation token
    pub continuation: Continuation,

    /// A working directory
    pub working_dir: T,

    /// Callbacks
    pub callbacks: C,
}

impl OsvWalker<(), ()> {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            path: None,
            continuation: Default::default(),
            working_dir: (),
            callbacks: (),
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Continuation(Option<String>);

impl<C, T> OsvWalker<C, T>
where
    C: Callbacks + Send + 'static,
    T: WorkingDirectory + Send + 'static,
{
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
    ) -> OsvWalker<C, U> {
        OsvWalker {
            source: self.source,
            path: self.path,
            continuation: self.continuation,
            callbacks: self.callbacks,
            working_dir,
        }
    }

    pub fn callbacks<U: Callbacks + Send + 'static>(self, callbacks: U) -> OsvWalker<U, T> {
        OsvWalker {
            source: self.source,
            path: self.path,
            continuation: self.continuation,
            callbacks,
            working_dir: self.working_dir,
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

    /// Sync version, as all git functions are sync
    #[instrument(skip(self), ret)]
    fn run_sync(mut self) -> Result<Continuation, Error> {
        log::debug!("Starting run for: {}", self.source);

        let working_dir = self
            .working_dir
            .create()
            .map_err(|err| Error::WorkingDir(Box::new(err)))?;

        let path = working_dir.as_ref();

        log::info!("Cloning {} into {}", self.source, path.display());

        let mut cb = RemoteCallbacks::new();
        cb.transfer_progress(|progress| {
            let received = progress.received_objects();
            let total = progress.total_objects();
            let bytes = progress.received_bytes();

            log::trace!("Progress - objects: {received} of {total}, bytes: {bytes}");

            true
        });

        let mut fo = FetchOptions::new();
        fo.remote_callbacks(cb);

        // clone or open repository

        let repo = match RepoBuilder::new()
            .fetch_options(fo)
            .clone(&self.source, path)
        {
            Ok(repo) => repo,
            Err(err) if err.code() == ErrorCode::Exists && err.class() == ErrorClass::Invalid => {
                log::info!("Already exists, opening ...");
                let repo = Repository::open(path)?;

                {
                    let mut remote = repo.find_remote("origin")?;
                    remote.fetch(&[] as &[&str], None, None)?;
                    remote.disconnect()?;

                    let head = repo.find_reference("FETCH_HEAD")?;
                    let head = head.peel_to_commit()?;

                    // reset to the most recent commit
                    repo.reset(head.as_object(), ResetType::Hard, None)?;
                }

                repo
            }
            Err(err) => {
                log::info!(
                    "Clone failed - code: {:?}, class: {:?}",
                    err.code(),
                    err.class()
                );
                return Err(err.into());
            }
        };

        log::debug!("Repository cloned or updated");

        // discover files between "then" and now

        let changes = match &self.continuation.0 {
            Some(commit) => {
                log::info!("Continuing from: {commit}");

                let start = repo.find_commit(repo.revparse_single(commit)?.id())?;
                let end = repo.head()?.peel_to_commit()?;

                let start = start.tree()?;
                let end = end.tree()?;

                let diff = repo.diff_tree_to_tree(Some(&start), Some(&end), None)?;

                let mut files = HashSet::with_capacity(diff.deltas().len());

                for delta in diff.deltas() {
                    if let Some(path) = delta.new_file().path() {
                        let path = match &self.path {
                            // files are relative to the base dir
                            Some(base) => match path.strip_prefix(base) {
                                Ok(path) => Some(path.to_path_buf()),
                                Err(..) => None,
                            },
                            // files are relative to the repo
                            None => Some(path.to_path_buf()),
                        };

                        if let Some(path) = path {
                            log::debug!("Record {} as changed file", path.display());
                            files.insert(path);
                        }
                    }
                }

                log::info!("Detected {} changed files", files.len());

                Some(files)
            }
            _ => {
                log::debug!("Ingesting all files");
                None
            }
        };

        // discover and process files

        let mut path = Cow::Borrowed(path);
        if let Some(base) = &self.path {
            path = path.join(base).into();
        }

        self.walk(&path, &changes)?;

        let head = repo.head()?;
        let commit = head.peel_to_commit()?.id();
        log::info!("Most recent commit: {commit}");

        // only drop when we are done, as this might delete the working directory

        drop(working_dir);

        // return result

        Ok(Continuation(Some(commit.to_string())))
    }

    fn walk(&mut self, base: &Path, changes: &Option<HashSet<PathBuf>>) -> Result<(), Error> {
        for entry in WalkDir::new(base)
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
            let path = path.strip_prefix(base).unwrap_or(path);

            if let Some(changes) = changes {
                log::trace!("Test if {} has changed", path.display());

                if !changes.contains(path) {
                    log::debug!("Skipping {}, as file did not change", path.display());
                    continue;
                }
            }

            match self.process_file(entry.path(), path) {
                Ok(()) => {}
                Err(ProcessingError::Critical(err)) => return Err(Error::Processing(err)),
                Err(err) => {
                    log::warn!("Failed to process file ({}): {err}", entry.path().display());
                    self.callbacks
                        .loading_error(path.to_path_buf(), err.to_string());
                }
            }
        }

        Ok(())
    }

    fn process_file(&mut self, path: &Path, rel_path: &Path) -> Result<(), ProcessingError> {
        let osv: Vulnerability = match path.extension().map(|s| s.to_string_lossy()).as_deref() {
            Some("yaml") => serde_yaml::from_reader(BufReader::new(std::fs::File::open(path)?))?,
            Some("json") => serde_json::from_reader(BufReader::new(std::fs::File::open(path)?))?,
            e => {
                log::debug!("Skipping unknown extension: {e:?}");
                return Ok(());
            }
        };

        log::debug!(
            "OSV: {} ({})",
            osv.id,
            osv.summary.as_deref().unwrap_or("n/a")
        );

        self.callbacks
            .process(rel_path, osv)
            .map_err(ProcessingError::Critical)?;

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

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

    struct Parse;

    impl Callbacks for Parse {
        fn process(&mut self, _path: &Path, osv: Vulnerability) -> Result<(), anyhow::Error> {
            let data = serde_json::to_vec(&osv)?;
            let _osv: trustify_module_ingestor::service::advisory::osv::schema::Vulnerability =
                serde_json::from_slice(&data)?;

            Ok(())
        }
    }

    #[test_log::test(tokio::test)]
    async fn test_walker() {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from("target/test.data/test_walker.git");

        let cont = Continuation::default();

        let walker = OsvWalker::new(SOURCE)
            .path(Some("vulns"))
            .continuation(cont)
            .callbacks(Parse)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = OsvWalker::new(SOURCE)
            .path(Some("vulns"))
            .continuation(cont)
            .callbacks(Parse)
            .working_dir(path);

        walker.run().await.expect("should not fail");
    }

    /// reset a git repository to the spec and return the commit as continuation
    fn git_reset(path: &Path, spec: &str) -> anyhow::Result<Continuation> {
        let repo = Repository::open(path)?;

        let r#ref = repo.revparse_single(spec)?;
        repo.reset(&r#ref, ResetType::Hard, None)?;

        let commit = r#ref.peel_to_commit()?.id().to_string();

        Ok(Continuation(Some(commit)))
    }
}
