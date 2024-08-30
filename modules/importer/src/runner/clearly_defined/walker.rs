use crate::runner::common::Error;
use crate::{
    model::ClearlyDefinedPackageType,
    runner::common::{
        processing_error::ProcessingError,
        walker::{CallbackError, Callbacks, Handler, HandlerError},
    },
};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

pub struct ClearlyDefinedHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    pub callbacks: C,
    pub types: HashSet<ClearlyDefinedPackageType>,
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

#[cfg(test)]
mod test {
    use crate::{
        model::DEFAULT_SOURCE_CLEARLY_DEFINED,
        runner::common::walker::{git_reset, Continuation, GitWalker},
    };
    use std::path::PathBuf;

    #[test_log::test(tokio::test)]
    async fn test_clearly_defined_walker() {
        let path = PathBuf::from(format!(
            "{}target/test.data/test_clearly_defined_walker.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));

        let cont = Continuation::default();

        let walker = GitWalker::new(DEFAULT_SOURCE_CLEARLY_DEFINED, ())
            .continuation(cont)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = GitWalker::new(DEFAULT_SOURCE_CLEARLY_DEFINED, ())
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");
    }
}
