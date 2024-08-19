mod walker;

use crate::{
    model::ClearlyDefinedImporter,
    runner::{
        clearly_defined::walker::ClearlyDefinedWalker,
        common::walker::{CallbackError, Callbacks},
        context::RunContext,
        report::{Phase, ReportBuilder, ScannerError},
        RunOutput,
    },
};
use parking_lot::Mutex;
use std::{path::Path, path::PathBuf, sync::Arc};
use tokio::runtime::Handle;
use tokio_util::io::ReaderStream;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Format, IngestorService},
};

struct Context<C: RunContext + 'static> {
    context: C,
    source: String,
    labels: Labels,
    report: Arc<Mutex<ReportBuilder>>,
    ingestor: IngestorService,
}

impl<C: RunContext> Context<C> {
    fn store(&self, path: &Path, data: Vec<u8>) -> anyhow::Result<()> {
        self.report.lock().tick();

        Handle::current().block_on(async {
            self.ingestor
                .ingest(
                    Labels::new()
                        .add("source", &self.source)
                        .add("importer", self.context.name())
                        .add("file", path.to_string_lossy())
                        .extend(&self.labels.0),
                    None,
                    Format::ClearlyDefined,
                    ReaderStream::new(&*data),
                )
                .await
        })?;

        Ok(())
    }
}

impl<C: RunContext> Callbacks<Vec<u8>> for Context<C> {
    fn loading_error(&mut self, path: PathBuf, message: String) {
        self.report
            .lock()
            .add_error(Phase::Validation, path.to_string_lossy(), message);
    }

    fn process(&mut self, path: &Path, curation: Vec<u8>) -> Result<(), CallbackError> {
        println!("INNER");
        if let Err(err) = self.store(path, curation) {
            self.report
                .lock()
                .add_error(Phase::Upload, path.to_string_lossy(), err.to_string());
        }

        self.context.check_canceled_sync(|| CallbackError::Canceled)
    }
}

impl super::ImportRunner {
    #[instrument(skip(self), ret)]
    pub async fn run_once_clearly_defined(
        &self,
        context: impl RunContext + 'static,
        clearly_defined: ClearlyDefinedImporter,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor = IngestorService::new(Graph::new(self.db.clone()), self.storage.clone());

        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let continuation = serde_json::from_value(continuation).unwrap_or_default();

        // working dir

        let working_dir = self
            .create_working_dir("clearly_defined", &clearly_defined.source)
            .await?;

        // progress reporting

        let progress = context.progress(format!(
            "Import ClearlyDefined curation: {}",
            clearly_defined.source
        ));

        // run the walker

        let walker = ClearlyDefinedWalker::new(clearly_defined.source.clone())
            .types(clearly_defined.types)
            .continuation(continuation)
            .callbacks(Context {
                context,
                source: clearly_defined.source,
                labels: clearly_defined.common.labels,
                report: report.clone(),
                ingestor,
            })
            .progress(progress);

        let continuation = match working_dir {
            Some(working_dir) => walker.working_dir(working_dir).run().await,
            None => walker.run().await,
        }
        .map_err(|err| ScannerError::Normal {
            err: err.into(),
            output: RunOutput {
                report: report.lock().clone().build(),
                continuation: None,
            },
        })?;

        // extract the report

        let report = match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build();

        // return

        Ok(RunOutput {
            report,
            continuation: serde_json::to_value(continuation).ok(),
        })
    }
}