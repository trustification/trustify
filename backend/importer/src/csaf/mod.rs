use ::csaf::document::Category;
use ::csaf::Csaf;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::source::{DispatchSource, FileSource, HttpSource};
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
use csaf_walker::walker::Walker;
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::process::ExitCode;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use trustify_api::db::Transactional;
use trustify_api::system::InnerSystem;
use trustify_common::config::Database;
use url::Url;
use walker_common::fetcher::Fetcher;
use walker_common::utils::hex::Hex;
use walker_common::validate::ValidationOptions;

/// Run the importer
#[derive(clap::Args, Debug)]
pub struct ImportCsafCommand {
    #[command(flatten)]
    pub database: Database,

    /// Source URL or path
    #[arg(short, long)]
    pub(crate) source: String,
}

impl ImportCsafCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        env_logger::init();

        let system = InnerSystem::with_config(&self.database).await?;

        let filter = |name: &str| {
            // RHAT: we have advisories marked as "vex"
            if !name.starts_with("cve-") {
                return false;
            }

            // only work with 2023 data for now
            if !name.starts_with("cve-2023-") {
                return false;
            }

            true
        };

        //  because we still have GPG v3 signatures
        let options = ValidationOptions::new().validation_date(SystemTime::from(
            Date::from_calendar_date(2007, Month::January, 1)?
                .midnight()
                .assume_offset(UtcOffset::UTC),
        ));

        let source: DispatchSource = match Url::parse(&self.source) {
            Ok(url) => HttpSource::new(
                url,
                Fetcher::new(Default::default()).await?,
                Default::default(),
            )
            .into(),
            Err(_) => FileSource::new(&self.source, None)?.into(),
        };

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

                    match url.path_segments().and_then(|path| path.last()) {
                        Some(name) => {
                            if !filter(name) {
                                return Ok(());
                            }
                        }
                        None => return Ok(()),
                    }

                    if let Err(err) = process(&system, doc).await {
                        log::warn!("Failed to process {url}: {err}");
                    }

                    Ok(())
                }
            })
            .with_options(options);

        Walker::new(source.clone())
            .walk(RetrievingVisitor::new(source, visitor))
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}

async fn process(system: &InnerSystem, doc: ValidatedAdvisory) -> anyhow::Result<()> {
    let csaf = serde_json::from_slice::<Csaf>(&doc.data)?;

    if !matches!(csaf.document.category, Category::Vex) {
        // not a vex, we ignore it
        return Ok(());
    }

    log::info!("Ingesting: {}", doc.url);
    let sha256: String = match doc.sha256.clone() {
        Some(sha) => sha.expected.clone(),
        None => {
            let mut actual = Sha256::new();
            actual.update(&doc.data);
            let digest: Output<Sha256> = actual.finalize();
            Hex(&digest).to_lower()
        }
    };

    let advisory = system
        .ingest_advisory(
            &csaf.document.tracking.id,
            doc.url.as_ref(),
            &sha256,
            Transactional::None,
        )
        .await?;

    advisory.ingest_csaf(csaf).await?;

    Ok(())
}
