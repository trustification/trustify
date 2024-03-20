use csaf::Csaf;
use std::time::Instant;

use trustify_common::db::Transactional;
use trustify_module_graph::graph::Graph;

pub async fn ingest(
    system: &Graph,
    csaf: Csaf,
    sha256: &str,
    location: &str,
) -> anyhow::Result<i32> {
    let identifier = csaf.document.tracking.id.clone();

    log::debug!("Ingesting: {} from {}", identifier, location);

    let start = Instant::now();

    let advisory = system
        .ingest_advisory(&identifier, location, sha256, Transactional::None)
        .await?;

    advisory.ingest_csaf(csaf).await?;

    let duration = Instant::now() - start;
    log::info!(
        "Ingested: {} from {}: took {}",
        identifier,
        location,
        humantime::Duration::from(duration),
    );

    Ok(advisory.advisory.id)
}
