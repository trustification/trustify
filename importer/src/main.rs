use crate::csaf::walk_product_tree_branches;
use ::csaf::definitions::ProductIdT;
use ::csaf::document::Category;
use ::csaf::Csaf;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::source::{DispatchSource, FileOptions, FileSource};
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
use csaf_walker::walker::Walker;
use huevos_api::system::System;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use walker_common::validate::ValidationOptions;

mod csaf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let system = System::new("postgres", "eggs", "localhost", "huevos").await?;

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
    let options = ValidationOptions {
        validation_date: Some(SystemTime::from(
            Date::from_calendar_date(2007, Month::January, 1)
                .unwrap()
                .midnight()
                .assume_offset(UtcOffset::UTC),
        )),
    };

    let source = FileSource::new("../csaf-walker/data/vex", FileOptions::default())?;
    // let source = HttpSource { .. };
    let source: DispatchSource = source.into();

    let visitor = ValidationVisitor::new(move |doc: Result<ValidatedAdvisory, ValidationError>| {
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

    Ok(())
}

async fn process(ctx: &System, doc: ValidatedAdvisory) -> anyhow::Result<()> {
    let csaf = serde_json::from_slice::<Csaf>(&doc.data)?;

    if !matches!(csaf.document.category, Category::Vex) {
        // not a vex, we ignore it
        return Ok(());
    }

    log::info!("Ingesting: {}", doc.url);

    // ctx..ingest_cve(csaf).await?;

    for vuln in csaf.vulnerabilities.into_iter().flatten() {
        let id = match &vuln.cve {
            Some(cve) => cve,
            None => continue,
        };
        ctx.ingest_vulnerability(&id).await?;

        if let Some(ps) = &vuln.product_status {
            if let Some(affected) = &ps.known_affected {}
        }
    }

    Ok(())
}
