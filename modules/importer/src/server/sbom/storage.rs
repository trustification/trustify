use crate::server::report::ReportBuilder;
use async_trait::async_trait;
use parking_lot::Mutex;
use sbom_walker::validation::{
    ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError,
};
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use trustify_module_ingestor::service::IngestorService;
use walker_common::compression::decompress_opt;

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

pub struct StorageContext {
    source: String,
}

#[async_trait(?Send)]
impl ValidatedVisitor for StorageVisitor {
    type Error = StorageError;
    type Context = StorageContext;

    async fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        Ok(StorageContext {
            source: context.url.to_string(),
        })
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
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

        self.ingestor
            .ingest_sbom(&context.source, ReaderStream::new(data.as_ref()))
            .await
            .map_err(|err| StorageError::Storage(err.into()))?;

        Ok(())
    }
}
