use crate::server::report::ReportBuilder;
use async_trait::async_trait;
use csaf::Csaf;
use csaf_walker::{
    retrieve::RetrievedAdvisory,
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use trustify_graph::graph::Graph;
use trustify_module_ingestor::service::advisory;
use walker_common::utils::hex::Hex;

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
        let csaf = serde_json::from_slice::<Csaf>(&doc.data)
            .map_err(|err| StorageError::Storage(err.into()))?;

        let sha256 = match doc.sha256.clone() {
            Some(sha) => sha.expected,
            None => {
                let digest = Sha256::digest(&doc.data);
                Hex(&digest).to_lower()
            }
        };

        advisory::csaf::ingest(&self.system, csaf, &sha256, doc.url.as_str())
            .await
            .map_err(StorageError::Storage)?;
        Ok(())
    }
}
