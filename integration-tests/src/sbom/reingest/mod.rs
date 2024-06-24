//! Testing to re-ingest a document, ensuring there is not stale data
#![cfg(test)]

use bytes::Bytes;
use std::convert::Infallible;
use std::str::FromStr;
use test_context::futures::stream;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::query::Query;
use trustify_common::db::test::TrustifyContext;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;

/// We re-ingest two versions of the same quarkus SBOM. However, as the quarkus SBOM doesn't have
/// anything in common other than the filename (which doesn't matter), these are considered two
/// different SBOMs.
#[test_context(TrustifyContext, skip_teardown)]
#[instrument]
#[test(tokio::test)]
async fn reingest_diff(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let sbom = SbomService::new(db.clone());
    let ingest = IngestorService::new(graph, storage);

    // ingest the first version

    let result1 = ingest
        .ingest(
            "test",
            None,
            Format::SPDX,
            stream::once(async {
                Ok::<_, Infallible>(Bytes::from_static(include_bytes!(
                    "data/v1/quarkus-bom-2.13.8.Final-redhat-00004.json"
                )))
            }),
        )
        .await?;

    assert_eq!(result1.document_id, "https://access.redhat.com/security/data/sbom/beta/spdx/quarkus-bom-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf");

    // ingest the second version

    let result2 = ingest
        .ingest(
            "test",
            None,
            Format::SPDX,
            stream::once(async {
                Ok::<_, Infallible>(Bytes::from_static(include_bytes!(
                    "data/v2/quarkus-bom-2.13.8.Final-redhat-00004.json"
                )))
            }),
        )
        .await?;

    assert_eq!(
        result2.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-2.13.8.Final-redhat-00004"
    );

    // now start testing

    assert_ne!(result1.id, result2.id);

    let mut sbom1 = sbom
        .fetch_sbom(result1.id, ())
        .await?
        .expect("v1 must be found");
    log::info!("SBOM1: {sbom1:?}");

    let mut sbom2 = sbom
        .fetch_sbom(result2.id, ())
        .await?
        .expect("v2 must be found");
    log::info!("SBOM2: {sbom2:?}");

    // both sboms have different names

    assert_eq!(sbom1.name, "quarkus-bom");
    assert_eq!(sbom2.name, "quarkus-bom-2.13.8.Final-redhat-00004");
    assert_eq!(sbom1.described_by.len(), 1);
    assert_eq!(sbom2.described_by.len(), 1);

    // clear the ID as that one will be different
    sbom1.described_by[0].id = "".into();
    sbom2.described_by[0].id = "".into();
    assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

    // but both sboms can be found by the same purl

    let purl = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom";

    let sboms = sbom
        .find_related_sboms(
            Purl::from_str(purl).expect("must parse").qualifier_uuid(),
            Paginated::default(),
            Query::default(),
            (),
        )
        .await?;

    assert_eq!(sboms.total, 2);

    // done

    Ok(())
}
