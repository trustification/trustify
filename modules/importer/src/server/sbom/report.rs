use crate::server::context::RunContext;
use crate::server::{
    common::storage::StorageError,
    report::{Phase, ReportVisitor},
    sbom::storage::StorageVisitor,
};
use sbom_walker::{
    retrieve::RetrievalError,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError},
};
use trustify_module_ingestor::service;
use walker_common::utils::url::Urlify;

pub struct SbomReportVisitor<C: RunContext>(pub ReportVisitor<StorageVisitor<C>>);

impl<C: RunContext> ValidatedVisitor for SbomReportVisitor<C> {
    type Error = <StorageVisitor<C> as ValidatedVisitor>::Error;
    type Context = <StorageVisitor<C> as ValidatedVisitor>::Context;

    async fn visit_context(
        &self,
        context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.0.next.visit_context(context).await
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        let file = result.url().to_string();

        self.0.report.lock().tick();

        let result = self.0.next.visit_sbom(context, result).await;

        if let Err(err) = &result {
            match err {
                StorageError::Validation(ValidationError::Retrieval(
                    RetrievalError::InvalidResponse { code, .. },
                )) => {
                    self.0.report.lock().add_error(
                        Phase::Retrieval,
                        file,
                        format!("retrieval of document failed: {code}"),
                    );

                    if code.is_client_error() {
                        // If it's a client error, there's no need to re-try. We simply claim
                        // success after we logged it.
                        return Ok(());
                    }
                }
                StorageError::Validation(ValidationError::DigestMismatch {
                    expected,
                    actual,
                    ..
                }) => {
                    self.0.report.lock().add_error(
                        Phase::Validation,
                        file,
                        format!("digest mismatch - expected: {expected}, actual: {actual}"),
                    );

                    // If there's a digest error, we can't do much other than ignoring the
                    // current file. Once it gets updated, we can reprocess it.
                    return Ok(());
                }
                StorageError::Validation(ValidationError::Signature { error, .. }) => {
                    self.0.report.lock().add_error(
                        Phase::Validation,
                        file,
                        format!("unable to verify signature: {error}"),
                    );

                    // If there's a signature error, we can't do much other than ignoring the
                    // current file. Once it gets updated, we can reprocess it.
                    return Ok(());
                }
                StorageError::Processing(err) => {
                    self.0.report.lock().add_error(
                        Phase::Upload,
                        file,
                        format!("processing failed: {err}"),
                    );

                    // The file seems corrupt in some way, we can't deal with it until it got
                    // updated.
                    return Ok(());
                }
                StorageError::Storage(err) => {
                    self.0.report.lock().add_error(
                        Phase::Upload,
                        file,
                        format!("upload failed: {err}"),
                    );

                    match &err {
                        // db errors fail and bubble up
                        service::Error::Db(_) => {}
                        _ => {
                            // all others just get logged
                            return Ok(());
                        }
                    }
                }
                StorageError::Canceled => {
                    // propagate up
                    return Err(StorageError::Canceled);
                }
            }
        }

        result
    }
}
