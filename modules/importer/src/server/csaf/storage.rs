use crate::server::report::ReportBuilder;
use csaf_walker::validation::{
    ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError,
};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Format, IngestorService};
use walker_common::utils::url::Urlify;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Storage(anyhow::Error),
}

pub struct StorageVisitor {
    pub name: String,
    pub ingestor: IngestorService,
    /// the report to report our messages to
    pub report: Arc<Mutex<ReportBuilder>>,
    pub labels: Labels,
}

impl ValidatedVisitor for StorageVisitor {
    type Error = StorageError;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        let doc = result?;
        let location = doc.context.url().to_string();
        let file = doc.possibly_relative_url();
        let fmt = Format::from_bytes(&doc.data).map_err(|e| StorageError::Storage(e.into()))?;
        self.ingestor
            .ingest(
                Labels::new()
                    .add("source", &location)
                    .add("importer", &self.name)
                    .add("file", file)
                    .extend(&self.labels.0),
                None, /* CSAF tracks issuer internally */
                fmt,
                ReaderStream::new(doc.data.as_ref()),
            )
            .await
            .map_err(|err| StorageError::Storage(err.into()))?;

        Ok(())
    }
}
