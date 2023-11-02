use csaf::document::Category;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::source::{DispatchSource, FileOptions, FileSource};
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
use csaf_walker::walker::Walker;
use huevos_api::system::{Context, System};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let system = System::new("postgres", "eggs", "localhost", "huevos").await?;

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
                Some(name) if name.starts_with("cve-") => {
                    // ok, go ahead
                }
                Some(name) => {
                    // RHAT: we also have advisories with the "vex" type
                    log::info!("Ignoring non-vex file: {name}");
                    return Ok(());
                }
                None => return Ok(()),
            }

            if let Err(err) = system
                .transaction(|ctx| {
                    Box::pin(async move {
                        process(ctx, doc).await?;
                        Ok::<_, anyhow::Error>(())
                    })
                })
                .await
            {
                log::warn!("Failed to process {url}: {err}");
            }

            Ok(())
        }
    });

    Walker::new(source.clone())
        .walk(RetrievingVisitor::new(source, visitor))
        .await?;

    Ok(())
}

async fn process(ctx: Context<'_>, doc: ValidatedAdvisory) -> anyhow::Result<()> {
    let csaf = serde_json::from_slice::<csaf::Csaf>(&doc.data)?;

    if !matches!(csaf.document.category, Category::Vex) {
        // not a vex, we ignore it
        return Ok(());
    }

    ctx.vex().ingest_vex(csaf).await?;

    Ok(())
}
