#![cfg(test)]

use std::time::Instant;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::{db::test::TrustifyContext, hashing::Digests};
use trustify_module_ingestor::{graph::Graph, service::advisory::csaf::loader::CsafLoader};

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest(ctx: TrustifyContext) -> anyhow::Result<()> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let start = Instant::now();

    // let data = include_bytes!("../../../etc/test-data/csaf/CVE-2023-20862.json");
    let data = include_bytes!("../../../etc/test-data/csaf/cve-2023-33201.json");

    let digests = Digests::digest(data);
    CsafLoader::new(&graph)
        .load((), &data[..], &digests)
        .await?;

    let ingest_time = start.elapsed();

    log::info!("ingest: {}", humantime::Duration::from(ingest_time));

    Ok(())
}
