use crate::csaf::trace_product;
use ::csaf::definitions::{Branch, ProductIdT};
use ::csaf::document::Category;
use ::csaf::Csaf;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::source::{DispatchSource, FileOptions, FileSource};
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
use csaf_walker::walker::Walker;
use huevos_api::system::InnerSystem;
use huevos_common::purl::Purl;
use packageurl::PackageUrl;
use std::process::ExitCode;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use walker_common::validate::ValidationOptions;

mod csaf;

/// Run the importer
#[derive(clap::Args, Debug)]
pub struct Run {}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        env_logger::init();

        let system = InnerSystem::new("postgres", "eggs", "localhost", "huevos").await?;

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

    for vuln in csaf.vulnerabilities.iter().flatten() {
        let id = match &vuln.cve {
            Some(cve) => cve,
            None => continue,
        };

        let v = system.ingest_vulnerability(id).await?;

        if let Some(ps) = &vuln.product_status {
            for r in ps.fixed.iter().flatten() {
                for purl in resolve_purls(&csaf, r) {
                    let package = Purl::from(purl.clone());
                    system
                        .ingest_vulnerability_fixed(package, &v, "vex")
                        .await?
                }
            }
        }
    }

    Ok(())
}

/// get the purl of a branch
fn branch_purl(branch: &Branch) -> Option<&PackageUrl<'static>> {
    branch.product.as_ref().and_then(|name| {
        name.product_identification_helper
            .iter()
            .flat_map(|pih| pih.purl.as_ref())
            .next()
    })
}

/// resolve purls
fn resolve_purls<'a>(csaf: &'a Csaf, id: &'a ProductIdT) -> Vec<&'a PackageUrl<'static>> {
    let id = &id.0;
    let mut result = vec![];

    if let Some(tree) = &csaf.product_tree {
        for rel in tree.relationships.iter().flatten() {
            if &rel.full_product_name.product_id.0 != id {
                continue;
            }

            /*
            let id = match &rel.category {
                RelationshipCategory::DefaultComponentOf => &rel.product_reference,
                RelationshipCategory::OptionalComponentOf => &rel.product_reference,
            };*/
            let id = &rel.product_reference;

            let purls = trace_product(csaf, &id.0).into_iter().flat_map(branch_purl);
            result.extend(purls);
        }
    }

    result
}
