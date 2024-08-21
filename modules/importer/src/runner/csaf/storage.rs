use crate::runner::{common::storage::StorageError, context::RunContext, report::ReportBuilder};
use csaf_walker::validation::{
    ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError,
};
use parking_lot::Mutex;
use std::sync::Arc;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::IngestorService;
use walker_common::utils::url::Urlify;

pub struct StorageVisitor<C: RunContext> {
    pub context: C,
    pub ingestor: IngestorService,
    /// the report to report our messages to
    pub report: Arc<Mutex<ReportBuilder>>,
    pub labels: Labels,
}

impl<C: RunContext> ValidatedVisitor for StorageVisitor<C> {
    type Error = StorageError<ValidationError>;
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

        self.ingestor
            .ingest(
                Labels::new()
                    .add("source", &location)
                    .add("importer", self.context.name())
                    .add("file", file)
                    .extend(&self.labels.0),
                None, /* CSAF tracks issuer internally */
                &doc.data,
            )
            .await
            .map_err(StorageError::Storage)?;

        self.context.check_canceled(|| StorageError::Canceled).await
    }
}
