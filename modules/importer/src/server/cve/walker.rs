use crate::server::common::{
    processing_error::ProcessingError,
    walker::{
        CallbackError, Callbacks, Continuation, Error, GitWalker, Handler, HandlerError,
        WorkingDirectory,
    },
};
use cve::Cve;
use std::{collections::HashSet, io::BufReader, path::Path};
use tracing::instrument;

struct CveHandler<C>
where
    C: Callbacks<Cve> + Send + 'static,
{
    callbacks: C,
    years: HashSet<u16>,
    start_year: Option<u16>,
}

impl<C> Handler for CveHandler<C>
where
    C: Callbacks<Cve> + Send + 'static,
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
    C: Callbacks<Cve> + Send + 'static,
{
    fn process_file(&mut self, path: &Path, rel_path: &Path) -> Result<(), ProcessingError> {
        let cve: Cve = match path.extension().map(|s| s.to_string_lossy()).as_deref() {
            Some("json") => serde_json::from_reader(BufReader::new(std::fs::File::open(path)?))?,
            e => {
                log::debug!("Skipping unknown extension: {e:?}");
                return Ok(());
            }
        };

        log::trace!(
            "CVE ({}): {} ({:?})",
            rel_path.display(),
            cve.id(),
            cve.common_metadata()
        );

        self.callbacks
            .process(rel_path, cve)
            .map_err(|err| match err {
                CallbackError::Processing(err) => ProcessingError::Critical(err),
                CallbackError::Canceled => ProcessingError::Canceled,
            })?;

        Ok(())
    }
}

pub struct CveWalker<C, T>
where
    C: Callbacks<Cve>,
    T: WorkingDirectory + Send + 'static,
{
    walker: GitWalker<(), T>,
    callbacks: C,
    years: HashSet<u16>,
    start_year: Option<u16>,
}

impl CveWalker<(), ()> {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            walker: GitWalker::new(source, ()).path(Some("cves")),
            callbacks: (),
            years: Default::default(),
            start_year: None,
        }
    }
}

impl<C, T> CveWalker<C, T>
where
    C: Callbacks<Cve>,
    T: WorkingDirectory + Send + 'static,
{
    /// Set the working directory.
    ///
    /// Also see: [`GitWalker::working_dir`].
    pub fn working_dir<U: WorkingDirectory + Send + 'static>(
        self,
        working_dir: U,
    ) -> CveWalker<C, U> {
        CveWalker {
            walker: self.walker.working_dir(working_dir),
            callbacks: self.callbacks,
            years: self.years,
            start_year: self.start_year,
        }
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: Continuation) -> Self {
        self.walker = self.walker.continuation(continuation);
        self
    }

    pub fn years(mut self, years: HashSet<u16>) -> Self {
        self.years = years;
        self
    }

    pub fn start_year(mut self, start_year: Option<u16>) -> Self {
        self.start_year = start_year;
        self
    }

    pub fn callbacks<U: Callbacks<Cve> + Send + 'static>(self, callbacks: U) -> CveWalker<U, T> {
        CveWalker {
            walker: self.walker.handler(()),
            callbacks,
            years: self.years,
            start_year: self.start_year,
        }
    }

    /// Run the walker
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<Continuation, Error> {
        self.walker
            .handler(CveHandler {
                callbacks: self.callbacks,
                years: self.years,
                start_year: self.start_year,
            })
            .run()
            .await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{model::DEFAULT_SOURCE_CVEPROJECT, server::common::walker::git_reset};
    use std::path::PathBuf;

    /// test CVE walker, runs for a long time
    #[ignore]
    #[test_log::test(tokio::test)]
    async fn test_walker() {
        let path = PathBuf::from("target/test.data/test_cve_walker.git");

        let cont = Continuation::default();

        let walker = CveWalker::new(DEFAULT_SOURCE_CVEPROJECT)
            .continuation(cont)
            .working_dir(path.clone());

        let _cont = walker.run().await.expect("should not fail");

        let cont = git_reset(&path, "HEAD~2").expect("must not fail");

        let walker = CveWalker::new(DEFAULT_SOURCE_CVEPROJECT)
            .continuation(cont)
            .working_dir(path);

        walker.run().await.expect("should not fail");
    }
}
