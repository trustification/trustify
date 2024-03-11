use crate::progress::init_log_and_progress;
use ::csaf::{document::Category, Csaf};
use csaf_walker::{
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileSource, HttpSource},
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::process::ExitCode;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use trustify_api::db::Transactional;
use trustify_api::graph::Graph;
use trustify_common::config::Database;
use url::Url;
use walker_common::{fetcher::Fetcher, utils::hex::Hex, validate::ValidationOptions};

/// Run the importer
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

    #[arg(long, env, default_value_t = 1)]
    pub workers: usize,
}

impl ImportCsafCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let progress = init_log_and_progress()?;

        let system = Graph::with_external_config(&self.database).await?;

        //  because we still have GPG v3 signatures
        let options = ValidationOptions::new().validation_date(SystemTime::from(
            Date::from_calendar_date(2007, Month::January, 1)?
                .midnight()
                .assume_offset(UtcOffset::UTC),
        ));

        let source: DispatchSource = match Url::parse(&self.source) {
            Ok(mut url) => {
                if !self.full_source_url {
                    url = url.join("/.well-known/csaf/provider-metadata.json")?;
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

        // validate (called by retriever)

        let visitor =
            ValidationVisitor::new(move |doc: Result<ValidatedAdvisory, ValidationError>| {
                let system = system.clone();
                async move {
                    let doc = match doc {
                        Ok(doc) => doc,
                        Err(err) => {
                            log::warn!("Ignore error: {err}");
                            return Ok::<(), anyhow::Error>(());
                        }
                    };

                    let url = doc.url.clone();
                    log::debug!("processing: {url}");

                    if let Err(err) = process(&system, doc).await {
                        log::warn!("Failed to process {url}: {err}");
                    }

                    Ok(())
                }
            })
            .with_options(options);

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

        walker.walk_parallel(self.workers, visitor).await?;

        Ok(ExitCode::SUCCESS)
    }
}

/// Process a single, validated advisory
async fn process(system: &Graph, doc: ValidatedAdvisory) -> anyhow::Result<()> {
    let csaf = serde_json::from_slice::<Csaf>(&doc.data)?;

    if !matches!(csaf.document.category, Category::Vex) {
        // not a vex, we ignore it
        return Ok(());
    }

    log::info!("Ingesting: {}", doc.url);
    let sha256 = match doc.sha256.clone() {
        Some(sha) => sha.expected.clone(),
        None => {
            let digest = Sha256::digest(&doc.data);
            Hex(&digest).to_lower()
        }
    };

    let advisory = system
        .ingest_advisory(
            &csaf.document.tracking.id,
            doc.url.to_string(),
            sha256,
            Transactional::None,
        )
        .await?;

    advisory.ingest_csaf(csaf).await?;

    Ok(())
}
