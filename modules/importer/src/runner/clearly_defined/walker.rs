use crate::{
    model::ClearlyDefinedPackageType,
    runner::{
        common::{
            processing_error::ProcessingError,
            walker::{
                CallbackError, Callbacks, Continuation, Error, GitWalker, Handler, HandlerError,
                WorkingDirectory,
            },
        },
        progress::Progress,
    },
};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use tracing::instrument;

struct ClearlyDefinedHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    callbacks: C,
    types: HashSet<ClearlyDefinedPackageType>,
}

impl<C> Handler for ClearlyDefinedHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    type Error = Error;

    fn process(
        &mut self,
        path: &Path,
        relative_path: &Path,
    ) -> Result<(), HandlerError<Self::Error>> {
        if let Some(head) = relative_path.components().next() {
            if let Some(head) = head.as_os_str().to_str() {
                if self.types.iter().any(|e| e.matches(head)) {
                    // it's a kind we care about.
                    return match self.process_file(path, relative_path) {
                        Ok(()) => Ok(()),
                        Err(ProcessingError::Critical(err)) => {
                            Err(HandlerError::Processing(Error::Processing(err)))
                        }
                        Err(ProcessingError::Canceled) => Err(HandlerError::Canceled),
                        Err(err) => {
                            log::warn!("Failed to process file ({}): {err}", path.display());
                            self.callbacks
                                .loading_error(path.to_path_buf(), err.to_string());
                            Ok(())
                        }
                    };
                }
            }
        }

        Ok(())
    }
}

impl<C> ClearlyDefinedHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    fn process_file(&mut self, path: &Path, rel_path: &Path) -> Result<(), ProcessingError> {
        let curation = match path.extension().map(|s| s.to_string_lossy()).as_deref() {
            Some("yaml") => {
                let mut bytes = Vec::new();
                std::fs::File::open(path)?
                    .read_to_end(&mut bytes)
                    .map_err(|e| ProcessingError::Critical(e.into()))?;
                bytes
            }
            e => {
                log::debug!("Skipping unknown extension: {e:?}");
                return Ok(());
            }
        };

        self.callbacks
            .process(rel_path, curation)
            .map_err(|err| match err {
                CallbackError::Processing(err) => ProcessingError::Critical(err),
                CallbackError::Canceled => ProcessingError::Canceled,
            })?;

        Ok(())
    }
}

pub struct ClearlyDefinedWalker<C, T, P>
where
    C: Callbacks<Vec<u8>>,
    T: WorkingDirectory + Send + 'static,
    P: Progress,
{
    walker: GitWalker<(), T, ()>,
    types: HashSet<ClearlyDefinedPackageType>,
    callbacks: C,
    progress: P,
}

impl ClearlyDefinedWalker<(), (), ()> {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            walker: GitWalker::new(source, ()).path(Some("curations")),
            types: HashSet::default(),
            callbacks: (),
            progress: (),
        }
    }

    pub fn types(mut self, types: HashSet<ClearlyDefinedPackageType>) -> Self {
        self.types = types;
        self
    }
}

impl<C, T, P> ClearlyDefinedWalker<C, T, P>
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
    ) -> ClearlyDefinedWalker<C, U, P> {
        ClearlyDefinedWalker {
            walker: self.walker.working_dir(working_dir),
            types: self.types,
            callbacks: self.callbacks,
            progress: self.progress,
        }
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: Continuation) -> Self {
        self.walker = self.walker.continuation(continuation);
        self
    }

    pub fn callbacks<U: Callbacks<Vec<u8>> + Send + 'static>(
        self,
        callbacks: U,
    ) -> ClearlyDefinedWalker<U, T, P> {
        ClearlyDefinedWalker {
            walker: self.walker,
            types: self.types,
            callbacks,
            progress: self.progress,
        }
    }

    pub fn progress<U: Progress + Send + 'static>(
        self,
        progress: U,
    ) -> ClearlyDefinedWalker<C, T, U> {
        ClearlyDefinedWalker {
            walker: self.walker,
            types: self.types,
            callbacks: self.callbacks,
            progress,
        }
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<Continuation, Error> {
        self.walker
            .handler(ClearlyDefinedHandler {
                callbacks: self.callbacks,
                types: self.types,
            })
            .progress(self.progress)
            .run()
            .await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{model::DEFAULT_SOURCE_CLEARLY_DEFINED, runner::common::walker::git_reset};
    use std::path::PathBuf;

    #[test_log::test(tokio::test)]
    async fn test_walker() {
        let path = PathBuf::from("target/test.data/test_clearly_defined_walker.git");

        let cont = Continuation::default();

        let walker = ClearlyDefinedWalker::new(DEFAULT_SOURCE_CLEARLY_DEFINED)
            .types(HashSet::from([ClearlyDefinedPackageType::Crate]))
            .continuation(cont)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~1").expect("must not fail");

        let walker = ClearlyDefinedWalker::new(DEFAULT_SOURCE_CLEARLY_DEFINED)
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");
    }
}
