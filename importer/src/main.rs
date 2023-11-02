use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::source::{DispatchSource, FileOptions, FileSource, HttpSource};
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
use csaf_walker::walker::Walker;
use huevos_api::system::{Context, System};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let system = System::start().await?;

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

    // TODO: implement

    Ok(())
}
