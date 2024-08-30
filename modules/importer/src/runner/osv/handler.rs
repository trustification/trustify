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
