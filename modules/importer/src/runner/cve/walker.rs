use crate::runner::common::Error;
use crate::runner::common::{
    processing_error::ProcessingError,
    walker::{CallbackError, Callbacks, Handler, HandlerError},
};
use std::fs::File;
use std::io::Read;
use std::{collections::HashSet, path::Path};

pub struct CveHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    pub callbacks: C,
    pub years: HashSet<u16>,
    pub start_year: Option<u16>,
}

impl<C> Handler for CveHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    type Error = Error;

    fn process(
        &mut self,
        path: &Path,
        relative_path: &Path,
    ) -> Result<(), HandlerError<Self::Error>> {
        // Get the year, as we walk with a base of `cves`, that must be the year folder.
        // If it is not, we skip it.
        let Some(year) = relative_path
            .iter()
            .next()
            .and_then(|s| s.to_string_lossy().parse::<u16>().ok())
        else {
            return Ok(());
        };

        // check the set of years
        if !self.years.is_empty() && !self.years.contains(&year) {
            return Ok(());
        }

        // check starting year
        if let Some(start_year) = self.start_year {
            if year < start_year {
                return Ok(());
            }
        }

        match self.process_file(path, relative_path) {
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
        }
    }
}

impl<C> CveHandler<C>
where
    C: Callbacks<Vec<u8>> + Send + 'static,
{
    fn process_file(&mut self, path: &Path, rel_path: &Path) -> Result<(), ProcessingError> {
        let cve = match path.extension().map(|s| s.to_string_lossy()).as_deref() {
            Some("json") => {
                let mut data = Vec::new();
                File::open(path)?.read_to_end(&mut data)?;
                data
            }
            e => {
                log::debug!("Skipping unknown extension: {e:?}");
                return Ok(());
            }
        };

        self.callbacks
            .process(rel_path, cve)
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
        model::DEFAULT_SOURCE_CVEPROJECT,
        runner::common::walker::{git_reset, Continuation, GitWalker},
    };
    use std::path::PathBuf;

    /// test CVE walker, runs for a long time
    #[ignore]
    #[test_log::test(tokio::test)]
    async fn test_cve_walker() {
        let path = PathBuf::from(format!(
            "{}target/test.data/test_cve_walker.git",
            env!("CARGO_WORKSPACE_ROOT")
        ));

        let cont = Continuation::default();

        let walker = GitWalker::new(DEFAULT_SOURCE_CVEPROJECT, ())
            .continuation(cont)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = GitWalker::new(DEFAULT_SOURCE_CVEPROJECT, ())
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");
    }
}
