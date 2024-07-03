use crate::server::common::{
    processing_error::ProcessingError,
    walker::{
        CallbackError, Callbacks, Continuation, Error, GitWalker, Handler, HandlerError,
        WorkingDirectory,
    },
};
use osv::schema::Vulnerability;
use std::{io::BufReader, path::Path};
use tracing::instrument;

struct OsvHandler<C>(C)
where
    C: Callbacks<Vulnerability> + Send + 'static;

impl<C> Handler for OsvHandler<C>
where
    C: Callbacks<Vulnerability> + Send + 'static,
{
    type Error = Error;

    fn process(
        &mut self,
        path: &Path,
        relative_path: &Path,
    ) -> Result<(), HandlerError<Self::Error>> {
        match self.process_file(path, relative_path) {
            Ok(()) => Ok(()),
            Err(ProcessingError::Critical(err)) => {
                Err(HandlerError::Processing(Error::Processing(err)))
            }
            Err(ProcessingError::Canceled) => Err(HandlerError::Canceled),
            Err(err) => {
                log::warn!("Failed to process file ({}): {err}", path.display());
                self.0.loading_error(path.to_path_buf(), err.to_string());
                Ok(())
            }
        }
    }
}

impl<C> OsvHandler<C>
where
    C: Callbacks<Vulnerability> + Send + 'static,
{
    fn process_file(&mut self, path: &Path, rel_path: &Path) -> Result<(), ProcessingError> {
        let osv: Vulnerability = match path.extension().map(|s| s.to_string_lossy()).as_deref() {
            Some("yaml") => serde_yaml::from_reader(BufReader::new(std::fs::File::open(path)?))?,
            Some("json") => serde_json::from_reader(BufReader::new(std::fs::File::open(path)?))?,
            e => {
                log::debug!("Skipping unknown extension: {e:?}");
                return Ok(());
            }
        };

        log::trace!(
            "OSV: {} ({})",
            osv.id,
            osv.summary.as_deref().unwrap_or("n/a")
        );

        self.0.process(rel_path, osv).map_err(|err| match err {
            CallbackError::Processing(err) => ProcessingError::Critical(err),
            CallbackError::Canceled => ProcessingError::Canceled,
        })?;

        Ok(())
    }
}

pub struct OsvWalker<C, T>
where
    C: Callbacks<Vulnerability>,
    T: WorkingDirectory + Send + 'static,
{
    walker: GitWalker<OsvHandler<C>, T>,
}

impl OsvWalker<(), ()> {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            walker: GitWalker::new(source, OsvHandler(())),
        }
    }
}

impl<C, T> OsvWalker<C, T>
where
    C: Callbacks<Vulnerability>,
    T: WorkingDirectory + Send + 'static,
{
    /// Set the working directory.
    ///
    /// Also see: [`GitWalker::working_dir`].
    pub fn working_dir<U: WorkingDirectory + Send + 'static>(
        self,
        working_dir: U,
    ) -> OsvWalker<C, U> {
        OsvWalker {
            walker: self.walker.working_dir(working_dir),
        }
    }

    pub fn path(mut self, path: Option<impl Into<String>>) -> Self {
        self.walker = self.walker.path(path);
        self
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: Continuation) -> Self {
        self.walker = self.walker.continuation(continuation);
        self
    }

    pub fn callbacks<U: Callbacks<Vulnerability> + Send + 'static>(
        self,
        callbacks: U,
    ) -> OsvWalker<U, T> {
        OsvWalker {
            walker: self.walker.handler(OsvHandler(callbacks)),
        }
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<Continuation, Error> {
        self.walker.run().await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::common::walker::git_reset;
    use std::path::PathBuf;

    #[test_log::test(tokio::test)]
    async fn test_walker() {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from("target/test.data/test_walker.git");

        let cont = Continuation::default();

        let walker = OsvWalker::new(SOURCE)
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = OsvWalker::new(SOURCE)
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");
    }

    /// ensure that using `path`, we can't escape the repo directory
    #[test_log::test(tokio::test)]
    async fn test_walker_fail_escape() {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from("target/test.data/test_walker_fail_escape.git");

        let cont = Continuation::default();

        let walker = OsvWalker::new(SOURCE)
            .path(Some("/etc"))
            .continuation(cont)
            .working_dir(path.clone());

        let r = walker.run().await;

        // must fail as we try to escape the repository root
        assert!(r.is_err());
    }
}
