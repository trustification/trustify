use crate::runner::common::Error;
use crate::runner::common::{
    processing_error::ProcessingError,
    walker::{CallbackError, Callbacks, Handler, HandlerError},
};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct OsvHandler<C>(pub C)
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

#[cfg(test)]
mod test {
    use crate::runner::common::walker::{git_reset, Continuation, GitWalker};
    use std::path::PathBuf;

    #[test_log::test(tokio::test)]
    async fn test_osv_walker() -> Result<(), anyhow::Error> {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from(format!(
            "{}target/test.data/test_walker.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));
        if path.exists() {
            std::fs::remove_dir_all(path.clone())?;
        }

        let cont = Continuation::default();

        let walker = GitWalker::new(SOURCE, ())
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path.clone())
            .depth(3);

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = GitWalker::new(SOURCE, ())
            .path(Some("vulns"))
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");

        Ok(())
    }

    /// ensure that using `path`, we can't escape the repo directory
    #[test_log::test(tokio::test)]
    async fn test_osv_walker_fail_escape() {
        const SOURCE: &str = "https://github.com/RConsortium/r-advisory-database";
        let path = PathBuf::from(format!(
            "{}target/test.data/test_walker_fail_escape.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));

        let cont = Continuation::default();

        let walker = GitWalker::new(SOURCE, ())
            .path(Some("/etc"))
            .continuation(cont)
            .working_dir(path.clone());

        let r = walker.run().await;

        // must fail as we try to escape the repository root
        assert!(r.is_err());
    }
}
