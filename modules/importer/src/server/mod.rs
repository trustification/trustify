pub mod context;
pub(crate) mod progress;

use crate::{
    model::{Importer, State},
    runner::{
        report::{Report, ScannerError},
        ImportRunner,
    },
    server::context::ServiceRunContext,
    service::ImporterService,
};
use std::{path::PathBuf, time::Duration};
use time::OffsetDateTime;
use tokio::time::MissedTickBehavior;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// run the importer loop
pub async fn importer(
    db: Database,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    Server {
        db,
        storage,
        working_dir,
    }
    .run()
    .await
}

#[derive(Clone, Debug)]
pub struct RunOutput {
    pub report: Report,
    pub continuation: Option<serde_json::Value>,
}

impl From<Report> for RunOutput {
    fn from(report: Report) -> Self {
        Self {
            report,
            continuation: None,
        }
    }
}

/// Single node, single process importer processor.
struct Server {
    db: Database,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
}

impl Server {
    #[instrument(skip_all, ret)]
    async fn run(&self) -> anyhow::Result<()> {
        let service = ImporterService::new(self.db.clone());

        self.reset_all_jobs(&service).await?;

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            log::debug!("checking importers");

            let importers = service.list().await?;
            for importer in importers {
                // FIXME: could add that to the query/list operation
                if importer.data.configuration.disabled || can_wait(&importer) {
                    continue;
                }

                log::debug!("  {}: {:?}", importer.name, importer.data.configuration);

                service.update_start(&importer.name, None).await?;

                // record timestamp before processing, so that we can use it as "since" marker
                let last_run = OffsetDateTime::now_utc();

                log::info!("Starting run: {}", importer.name);

                let context = ServiceRunContext::new(service.clone(), importer.name.clone());

                let runner = ImportRunner {
                    db: self.db.clone(),
                    storage: self.storage.clone(),
                    working_dir: self.working_dir.clone(),
                };

                let (last_error, report, continuation) = match runner
                    .run_once(
                        context,
                        importer.data.configuration,
                        importer.data.last_success,
                        importer.data.continuation,
                    )
                    .await
                {
                    Ok(RunOutput {
                        report,
                        continuation,
                    }) => (None, Some(report), continuation),
                    Err(ScannerError::Normal {
                        err,
                        output:
                            RunOutput {
                                report,
                                continuation,
                            },
                    }) => (Some(err.to_string()), Some(report), continuation),
                    Err(ScannerError::Critical(err)) => (Some(err.to_string()), None, None),
                };

                log::info!("Import run complete: {last_error:?}");

                service
                    .update_finish(
                        &importer.name,
                        None,
                        last_run,
                        last_error,
                        continuation,
                        report.and_then(|report| serde_json::to_value(report).ok()),
                    )
                    .await?;
            }
        }
    }

    /// Reset all jobs back into non-running state.
    ///
    /// This is intended when the application starts up, to reset stale job states. Making it
    /// possible to re-run them when they are due.
    ///
    /// **NOTE:** we can only do this as we're intended to be a single-process worker.
    async fn reset_all_jobs(&self, service: &ImporterService) -> anyhow::Result<()> {
        for importer in service.list().await? {
            if importer.data.state == State::Running {
                log::info!(
                    "Cleaning up stale importer job during startup: {} (since: {})",
                    importer.name,
                    importer.data.last_change
                );
                service
                    .update_finish(
                        &importer.name,
                        None,
                        // either use the last run, or fall back to the last time the state changed
                        importer.data.last_run.unwrap_or(importer.data.last_change),
                        Some("Import cancelled".into()),
                        None,
                        None,
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

/// check if we need to run or skip the importer
fn can_wait(importer: &Importer) -> bool {
    let Some(last) = importer.data.last_run else {
        return false;
    };

    (OffsetDateTime::now_utc() - last) < importer.data.configuration.period
}
