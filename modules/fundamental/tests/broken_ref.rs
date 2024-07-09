//! Testing broken references
#![allow(clippy::expect_used)]

use bytes::Bytes;
use std::convert::Infallible;
use test_context::futures::stream;
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn ingest_spdx_broken_refs(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let data = include_bytes!("../../../etc/test-data/spdx/broken-refs.json");

    let (storage, _tmp) = FileSystemBackend::for_test().await?;

    let ingestor = IngestorService::new(graph, storage);
    let sbom = SbomService::new(db);

    let err = ingestor
        .ingest(
            ("source", "test"),
            None,
            Format::sbom_from_bytes(data)?,
            stream::iter([Ok::<_, Infallible>(Bytes::from_static(data))]),
        )
        .await
        .expect_err("must not ingest");

    assert_eq!(
        err.to_string(),
        "Invalid SPDX reference: SPDXRef-0068e307-de91-4e82-b407-7a41217f9758"
    );

    let result = sbom
        .fetch_sboms(Default::default(), Default::default(), (), ())
        .await?;

    // there must be no traces, everything must be rolled back
    assert_eq!(result.total, 0);

    Ok(())
}
