use crate::server::report::ReportBuilder;
use async_trait::async_trait;
use csaf_walker::validation::{
    ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError,
};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use trustify_module_ingestor::service::IngestorService;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Storage(anyhow::Error),
}

pub struct StorageVisitor {
    pub ingestor: IngestorService,
    /// the report to report our messages to
    pub report: Arc<Mutex<ReportBuilder>>,
}

#[async_trait(? Send)]
impl ValidatedVisitor for StorageVisitor {
    type Error = StorageError;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        let doc = result?;
        let location = doc.context.url().to_string();

        self.ingestor
            .ingest(&location, ReaderStream::new(doc.data.as_ref()))
            .await
            .map_err(|err| StorageError::Storage(err.into()))?;

        Ok(())
    }
}
