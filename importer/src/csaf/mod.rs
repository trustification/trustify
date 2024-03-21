use crate::progress::init_log_and_progress;
use csaf_walker::{
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileSource, HttpSource},
    validation::ValidationVisitor,
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use trustify_common::{config::Database, db};
use trustify_module_graph::graph::Graph;
use trustify_module_importer::server::{
    common::validation,
    csaf::storage,
    report::{Report, ReportBuilder, ScannerError, SplitScannerError},
};
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::fs::FileSystemBackend;
use url::Url;
use walker_common::{fetcher::Fetcher, progress::Progress};

/// Import from a CSAF source
#[derive(clap::Args, Debug)]
pub struct ImportCsafCommand {
    #[command(flatten)]
    pub database: Database,

    /// Source URL or path
    pub source: String,

    /// If the source is a full source URL
    #[arg(long, env)]
    pub full_source_url: bool,

    /// Distribution URLs or ROLIE feed URLs to skip
    #[arg(long, env)]
    pub skip_url: Vec<String>,

    /// Only consider files having any of those prefixes. An empty list will accept all files.
    #[arg(long, env)]
    pub only_prefix: Vec<String>,

    /// number of concurrent workers
    #[arg(long, env, default_value_t = 1)]
    pub workers: usize,

    /// Location of the file storage
    #[arg(long, env)]
    pub storage: PathBuf,
}

impl ImportCsafCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let progress = init_log_and_progress()?;

        log::info!("Ingesting CSAF");

        let (report, result) = self.run_once(progress).await.split()?;

        log::info!("Import report: {report:#?}");

        result.map(|()| ExitCode::SUCCESS)
    }

    pub async fn run_once(self, progress: Progress) -> Result<Report, ScannerError> {
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let db = db::Database::with_external_config(&self.database, false).await?;
        let system = Graph::new(db);

        let source: DispatchSource = match Url::parse(&self.source) {
            Ok(mut url) => {
                if !self.full_source_url {
                    url = url
                        .join("/.well-known/csaf/provider-metadata.json")
                        .map_err(|err| ScannerError::Critical(err.into()))?;
                }
                log::info!("Provider metadata: {url}");
                HttpSource::new(
                    url,
                    Fetcher::new(Default::default()).await?,
                    Default::default(),
                )
                .into()
            }
            Err(_) => FileSource::new(&self.source, None)?.into(),
        };

        // storage (called by validator)

        let storage = FileSystemBackend::new(&self.storage).await?;
        let ingestor = IngestorService::new(system, storage);
        let visitor = storage::StorageVisitor {
            ingestor,
            report: report.clone(),
        };

        // validate (called by retriever)

        //  because we still have GPG v3 signatures
        let options = validation::options(true)?;
        let visitor = ValidationVisitor::new(visitor).with_options(options);

        // retrieve (called by filter)

        let visitor = RetrievingVisitor::new(source.clone(), visitor);

        //  filter (called by walker)

        let config = FilterConfig::new().extend_only_prefixes(self.only_prefix);
        let visitor = FilteringVisitor { config, visitor };

        // walker

        let mut walker = Walker::new(source).with_progress(progress);

        if !self.skip_url.is_empty() {
            // set up a distribution filter by URL
            let skip_urls = HashSet::<String>::from_iter(self.skip_url);
            walker = walker.with_distribution_filter(move |distribution| {
                skip_urls.contains(distribution.url().as_str())
            });
        }

        walker
            .walk_parallel(self.workers, visitor)
            .await // if the walker fails, we record the outcome as part of the report, but skip any
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
