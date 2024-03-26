use crate::server::report::ReportBuilder;
use async_trait::async_trait;
use csaf_walker::{
    retrieve::RetrievedAdvisory,
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use parking_lot::Mutex;
use std::io::BufReader;
use std::sync::Arc;
use trustify_module_graph::graph::Graph;
use trustify_module_ingestor::service::advisory::csaf::loader::CsafLoader;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Storage(anyhow::Error),
}

pub struct StorageVisitor {
    pub system: Graph,
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
        self.store(&result?.retrieved).await?;
        Ok(())
    }
}

impl StorageVisitor {
    async fn store(&self, doc: &RetrievedAdvisory) -> Result<(), StorageError> {
        let loader = CsafLoader::new(&self.system);

        loader
            .load(doc.url.as_str(), BufReader::new(doc.data.as_ref()))
            .await
            .map_err(|e| StorageError::Storage(e.into()))?;

        Ok(())
    }
}
