use crate::progress::init_log_and_progress;
use parking_lot::Mutex;
use sbom_walker::{
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileSource, HttpOptions, HttpSource},
    validation::ValidationVisitor,
    walker::Walker,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use trustify_common::{config::Database, db};
use trustify_module_graph::graph::Graph;
use trustify_module_importer::server::{
    common::validation,
    report::{Report, ReportBuilder, ScannerError, SplitScannerError},
    sbom::storage,
};
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::fs::FileSystemBackend;
use url::Url;
use walker_common::{fetcher::Fetcher, progress::Progress};

/// Import SBOMs
#[derive(clap::Args, Debug, Clone)]
pub struct ImportSbomCommand {
    #[command(flatten)]
    pub database: Database,

    /// GPG key used to sign SBOMs, use the fragment of the URL as fingerprint.
    #[arg(long, env)]
    pub key: Vec<Url>,

    /// Source URL or path
    pub source: String,

    /// Location of the file storage
    #[arg(long, env)]
    pub storage: PathBuf,
}

impl ImportSbomCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let progress = init_log_and_progress()?;

        log::info!("Ingesting SBOMs");

        let (report, result) = self.run_once(progress).await.split()?;

        log::info!("Import report: {report:#?}");

        result.map(|()| ExitCode::SUCCESS)
    }

    async fn run_once(self, progress: Progress) -> Result<Report, ScannerError> {
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let db =
            db::Database::with_external_config(&self.database, db::CreationMode::Default).await?;
        let system = Graph::new(db);

        let source: DispatchSource = match Url::parse(&self.source) {
            Ok(url) => {
                let keys = self
                    .key
                    .into_iter()
                    .map(|key| key.into())
                    .collect::<Vec<_>>();
                HttpSource::new(
                    url,
                    Fetcher::new(Default::default()).await?,
                    HttpOptions::new().keys(keys),
                )
                .into()
            }
            Err(_) => FileSource::new(&self.source, None)?.into(),
        };

        // storage (called by validator)

        let storage = FileSystemBackend::new(&self.storage).await?;
        let ingestor = IngestorService::new(system, storage);
        let storage = storage::StorageVisitor {
            ingestor,
            report: report.clone(),
        };

        // validate (called by retriever)

        //  because we still have GPG v3 signatures
        let options = validation::options(true)?;
        let validation = ValidationVisitor::new(storage).with_options(options);

        // retriever (called by filter)

        let visitor = RetrievingVisitor::new(source.clone(), validation);

        // walker

        Walker::new(source)
            .with_progress(progress)
            .walk(visitor)
            .await
            // if the walker fails, we record the outcome as part of the report, but skip any
            // further processing, like storing the marker
            .map_err(|err| ScannerError::Normal {
                err: err.into(),
                report: report.lock().clone().build(),
            })?;

        Ok(match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build())
    }
}
