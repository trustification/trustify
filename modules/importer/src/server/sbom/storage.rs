use crate::server::report::ReportBuilder;
use async_trait::async_trait;
use parking_lot::Mutex;
use sbom_walker::{
    retrieve::RetrievedSbom,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError},
    Sbom,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use trustify_common::db::Transactional;
use trustify_graph::graph::Graph;
use walker_common::{compression::decompress_opt, utils::hex::Hex};

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

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.store(&result?.retrieved).await?;
        Ok(())
    }
}

impl StorageVisitor {
    async fn store(&self, doc: &RetrievedSbom) -> Result<(), StorageError> {
        let (data, _compressed) = match decompress_opt(&doc.data, doc.url.path())
            .transpose()
            .map_err(StorageError::Storage)?
        {
            Some(data) => (data, true),
            None => (doc.data.clone(), false),
        };

        let sha256: String = match doc.sha256.clone() {
            Some(sha) => sha.expected.clone(),
            None => Hex(&Sha256::digest(&data)).to_lower(),
        };

        if Sbom::try_parse_any(&data).is_ok() {
            log::info!(
                "Storing: {} (modified: {:?})",
                doc.url,
                doc.metadata.last_modification
            );

            let sbom = self
                .system
                .ingest_sbom(doc.url.as_ref(), &sha256, Transactional::None)
                .await
                .map_err(|err| StorageError::Storage(err.into()))?;

            // FIXME: consider adding a report entry in case of "fixing" things
            sbom.ingest_spdx_data(data.as_ref())
                .await
                .map_err(StorageError::Storage)?;
        }

        Ok(())
    }
}
