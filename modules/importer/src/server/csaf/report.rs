use crate::server::{
    csaf::storage::{StorageError, StorageVisitor},
    report::{Phase, ReportVisitor, Severity},
};
use async_trait::async_trait;
use csaf_walker::{
    retrieve::RetrievalError,
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use walker_common::utils::url::Urlify;

pub struct CsafReportVisitor(pub ReportVisitor<StorageVisitor>);

#[async_trait(?Send)]
impl ValidatedVisitor for CsafReportVisitor {
    type Error = <StorageVisitor as ValidatedVisitor>::Error;
    type Context = <StorageVisitor as ValidatedVisitor>::Context;

    async fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        self.0.next.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        let file = result.url().to_string();

        self.0.report.lock().tick();

        let result = self.0.next.visit_advisory(context, result).await;

        if let Err(err) = &result {
            match err {
                StorageError::Validation(ValidationError::Retrieval(
                    RetrievalError::InvalidResponse { code, .. },
                )) => {
                    self.0.report.lock().add_error(
                        Phase::Retrieval,
                        file,
                        Severity::Error,
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
                        Severity::Error,
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
                        Severity::Error,
                        format!("unable to verify signature: {error}"),
                    );

                    // If there's a signature error, we can't do much other than ignoring the
                    // current file. Once it gets updated, we can reprocess it.
                }
                StorageError::Storage(err) => {
                    self.0.report.lock().add_error(
                        Phase::Upload,
                        file,
                        Severity::Error,
                        format!("upload failed: {err}"),
                    );
                }
            }
        }

        result
    }
}
