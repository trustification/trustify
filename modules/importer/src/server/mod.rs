pub mod context;
pub(crate) mod progress;

use crate::{
    model::Importer,
    runner::{
        ImportRunner,
        common::heartbeat::Heart,
        report::{Report, ScannerError},
    },
    server::context::ServiceRunContext,
    service::{Error, ImporterService},
};
use std::{collections::HashMap, path::PathBuf, time::Duration};
use time::OffsetDateTime;
use tokio::{task::LocalSet, time::MissedTickBehavior};
use tracing::instrument;
use trustify_common::db::Database;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// run the importer loop
pub async fn importer(
    db: Database,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
    analysis: Option<AnalysisService>,
    concurrency: usize,
) -> anyhow::Result<()> {
    Server {
        db,
        storage,
        working_dir,
        analysis,
        concurrency,
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
    analysis: Option<AnalysisService>,
    concurrency: usize,
}

impl Server {
    #[instrument(skip_all, ret)]
    async fn run(self) -> anyhow::Result<()> {
        // The Heart struct spawns locally because the import fn isn't
        // Send, so we need a LocalSet
        LocalSet::new().run_until(self.run_local()).await
    }

    async fn run_local(self) -> anyhow::Result<()> {
        let service = ImporterService::new(self.db.clone());
        let runner = ImportRunner {
            db: self.db.clone(),
            storage: self.storage.clone(),
            working_dir: self.working_dir.clone(),
            analysis: self.analysis.clone(),
        };
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Maintain a list of currently running jobs
        let mut runs = HashMap::<String, Heart>::default();

        loop {
            interval.tick().await;

            // Remove jobs that are finished; they're heartless ;)
            runs.retain(|_, heart| heart.is_beating());
            let count = runs.len();

            // Asynchronously fire off new jobs subject to max concurrency
            runs.extend(
                service
                    .list()
                    .await?
                    .into_iter()
                    .filter(|i| {
                        !(i.data.configuration.disabled || already_running(i) || can_wait(i))
                    })
                    .take(self.concurrency - count)
                    .map(|importer| {
                        (
                            importer.name.clone(),
                            Heart::new(
                                importer.clone(),
                                runner.db.clone(),
                                import(runner.clone(), importer, service.clone()),
                            ),
                        )
                    }),
            );
        }
    }
}

async fn import(
    runner: ImportRunner,
    importer: Importer,
    service: ImporterService,
) -> Result<(), Error> {
    log::debug!("  {}: {:?}", importer.name, importer.data.configuration);

    service.update_start(&importer.name, None).await?;

    // record timestamp before processing, so that we can use it as "since" marker
    let last_run = OffsetDateTime::now_utc();

    log::info!("Starting run: {}", importer.name);

    let context = ServiceRunContext::new(service.clone(), importer.name.clone());

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
            output: RunOutput {
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

    Ok(())
}

/// check if we need to run or skip the importer
fn can_wait(importer: &Importer) -> bool {
    let Some(last) = importer.data.last_run else {
        return false;
    };
    (OffsetDateTime::now_utc() - last) < importer.data.configuration.period
}

/// check if another instance is running this importer
fn already_running(importer: &Importer) -> bool {
    importer
        .heartbeat
        .and_then(|t| OffsetDateTime::from_unix_timestamp_nanos(t).ok())
        .is_some_and(|t| (OffsetDateTime::now_utc() - t) < (2 * Heart::RATE))
}
