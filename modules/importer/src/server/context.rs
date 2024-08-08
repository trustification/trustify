use crate::{runner::context::RunContext, service::ImporterService};
use std::{
    fmt::Debug,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::instrument;

/// Context for an import run
#[derive(Debug)]
pub struct ServiceRunContext {
    /// The name of the import job
    name: String,
    state: Mutex<CheckCancellation>,
}

impl ServiceRunContext {
    pub fn new(service: ImporterService, name: String) -> Self {
        Self {
            name: name.clone(),
            state: Mutex::new(CheckCancellation::new(
                service,
                name,
                Duration::from_secs(60),
            )),
        }
    }
}

impl RunContext for ServiceRunContext {
    fn name(&self) -> &str {
        &self.name
    }

    async fn is_canceled(&self) -> bool {
        self.state.lock().await.check().await
    }
}

#[derive(Debug)]
struct CheckCancellation {
    service: ImporterService,
    importer_name: String,

    canceled: bool,
    last_check: Instant,
    period: Duration,
}

impl CheckCancellation {
    pub fn new(service: ImporterService, importer_name: String, period: Duration) -> Self {
        Self {
            service,
            importer_name,
            canceled: false,
            last_check: Instant::now(),
            period,
        }
    }

    /// Check if the importer was canceled.
    ///
    /// Returns `true` if the reporter was canceled.
    pub async fn check(&mut self) -> bool {
        if !self.canceled && self.last_check.elapsed() > self.period {
            // If we are not canceled yet, and the check expired, we check again.
            // Also, if we encounter an error while checking, we abort, assuming we are canceled.
            self.canceled = self.perform_check().await.unwrap_or(true);
        }

        // return the last known state
        self.canceled
    }

    #[instrument(err)]
    async fn perform_check(&self) -> anyhow::Result<bool> {
        let importer = self.service.read(&self.importer_name).await?;

        // If we have a record, return its state.
        // If we don't have a record, we must have been deleted. Which also means we're canceled.
        Ok(importer
            .map(|importer| importer.value.data.configuration.disabled)
            .unwrap_or(true))
    }
}
