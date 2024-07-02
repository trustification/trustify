use crate::server::report::ReportBuilder;
use parking_lot::Mutex;
use sbom_walker::validation::{
    ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError,
};
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Format, IngestorService};
use walker_common::compression::decompress_opt;
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
    pub source: String,
    pub labels: Labels,
    pub ingestor: IngestorService,
    /// the report to report our messages to
    pub report: Arc<Mutex<ReportBuilder>>,
}

impl ValidatedVisitor for StorageVisitor {
    type Error = StorageError;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        let doc = result?;

        let (data, _compressed) = match decompress_opt(&doc.data, doc.url.path())
            .transpose()
            .map_err(StorageError::Storage)?
        {
            Some(data) => (data, true),
            None => (doc.data.clone(), false),
        };

        let file = doc.possibly_relative_url();

        let fmt = Format::sbom_from_bytes(&data).map_err(|e| StorageError::Storage(e.into()))?;

        self.ingestor
            .ingest(
                Labels::new()
                    .add("source", &self.source)
                    .add("importer", &self.name)
                    .add("file", file)
                    .extend(&self.labels.0),
                None,
                fmt,
                ReaderStream::new(data.as_ref()),
            )
            .await
            .map_err(|err| StorageError::Storage(err.into()))?;

        Ok(())
    }
}
