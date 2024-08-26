use crate::runner::{
    common::{
        processing_error::ProcessingError,
        walker::{
            CallbackError, Callbacks, Continuation, Error, GitWalker, Handler, HandlerError,
            WorkingDirectory,
        },
    },
    progress::Progress,
};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tracing::instrument;

struct OsvHandler<C>(C)
where
    C: Callbacks<Vec<u8>> + Send + 'static;

impl<C> Handler for OsvHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
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
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    fn process_file(&mut self, path: &Path, rel_path: &Path) -> Result<(), ProcessingError> {
        let osv = match path.extension().map(|s| s.to_string_lossy()).as_deref() {
            Some("yaml") | Some("json") => {
                let mut data = Vec::new();
                File::open(path)?.read_to_end(&mut data)?;
                data
            }
            e => {
                log::debug!("Skipping unknown extension: {e:?}");
                return Ok(());
            }
        };

        self.0.process(rel_path, osv).map_err(|err| match err {
            CallbackError::Processing(err) => ProcessingError::Critical(err),
            CallbackError::Canceled => ProcessingError::Canceled,
        })?;

        Ok(())
    }
}

pub struct OsvWalker<C, T, P>
where
    C: Callbacks<Vec<u8>>,
    T: WorkingDirectory + Send + 'static,
    P: Progress + Send + 'static,
{
    walker: GitWalker<OsvHandler<C>, T, P>,
}

impl OsvWalker<(), (), ()> {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            walker: GitWalker::new(source, OsvHandler(())),
        }
    }
}

impl<C, T, P> OsvWalker<C, T, P>
where
    C: Callbacks<Vec<u8>>,
    T: WorkingDirectory + Send + 'static,
    P: Progress + Send + 'static,
{
    /// Set the working directory.
    ///
    /// Also see: [`GitWalker::working_dir`].
    pub fn working_dir<U: WorkingDirectory + Send + 'static>(
        self,
        working_dir: U,
    ) -> OsvWalker<C, U, P> {
        OsvWalker {
            walker: self.walker.working_dir(working_dir),
        }
    }

    pub fn branch(mut self, branch: Option<impl Into<String>>) -> Self {
        self.walker = self.walker.branch(branch);
        self
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

    pub fn callbacks<U: Callbacks<Vec<u8>> + Send + 'static>(
        self,
        callbacks: U,
    ) -> OsvWalker<U, T, P> {
        OsvWalker {
            walker: self.walker.handler(OsvHandler(callbacks)),
        }
    }

    pub fn progress<U: Progress + Send + 'static>(self, progress: U) -> OsvWalker<C, T, U> {
        OsvWalker {
            walker: self.walker.progress(progress),
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
    use crate::runner::common::walker::git_reset;
    use std::path::PathBuf;

    #[test_log::test(tokio::test)]
    async fn test_walker() {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from(format!(
            "{}target/test.data/test_walker.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));

        let cont = Continuation::default();

        let walker = OsvWalker::new(SOURCE)
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~1").expect("must not fail");

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
        let path = PathBuf::from(format!(
            "{}target/test.data/test_walker_fail_escape.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));

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
