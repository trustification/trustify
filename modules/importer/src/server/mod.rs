pub mod common;
pub mod csaf;
pub mod report;
pub mod sbom;

use crate::model::{Importer, ImporterConfiguration};
use crate::server::report::{Report, ScannerError};
use crate::service::ImporterService;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::MissedTickBehavior;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// run the importer loop
pub async fn importer(db: Database, storage: DispatchBackend) -> anyhow::Result<()> {
    Server { db, storage }.run().await
}

struct Server {
    db: Database,
    storage: DispatchBackend,
}

impl Server {
    #[instrument(skip_all, err)]
    async fn run(&self) -> anyhow::Result<()> {
        let service = ImporterService::new(self.db.clone());

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

                let (last_error, report) = match self
                    .run_once(importer.data.configuration, importer.data.last_run)
                    .await
                {
                    Ok(report) => (None, Some(report)),
                    Err(ScannerError::Normal { err, report }) => {
                        (Some(err.to_string()), Some(report))
                    }
                    Err(ScannerError::Critical(err)) => (Some(err.to_string()), None),
                };

                log::info!("Import run complete: {last_error:?}");

                service
                    .update_finish(
                        &importer.name,
                        None,
                        last_run,
                        last_error,
                        report.and_then(|report| serde_json::to_value(report).ok()),
                    )
                    .await?;
            }
        }
    }

    #[instrument(skip_all, fields(), err, ret)]
    async fn run_once(
        &self,
        configuration: ImporterConfiguration,
        last_run: Option<OffsetDateTime>,
    ) -> Result<Report, ScannerError> {
        let last_run = last_run.map(|t| t.into());

        match configuration {
            ImporterConfiguration::Sbom(sbom) => self.run_once_sbom(sbom, last_run).await,
            ImporterConfiguration::Csaf(csaf) => self.run_once_csaf(csaf, last_run).await,
        }
    }
}

/// check if we need to run or skip the importer
fn can_wait(importer: &Importer) -> bool {
    let Some(last) = importer.data.last_run else {
        return false;
    };

    (OffsetDateTime::now_utc() - last) < importer.data.configuration.period
}
