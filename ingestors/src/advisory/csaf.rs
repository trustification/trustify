use csaf::Csaf;

use trustify_common::db::Transactional;
use trustify_graph::graph::Graph;

pub async fn ingest(
    system: &Graph,
    csaf: Csaf,
    sha256: &str,
    location: &str,
) -> anyhow::Result<i32> {
    let identifier = &csaf.document.tracking.id;

    log::info!("Ingesting: {} from {}", identifier, location);

    let advisory = system
        .ingest_advisory(identifier, location, sha256, Transactional::None)
        .await?;

    advisory.ingest_csaf(csaf).await?;

    Ok(advisory.advisory.id)
}
