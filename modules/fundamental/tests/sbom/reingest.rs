use bytes::Bytes;
use serde_json::Value;
use std::str::FromStr;
use test_context::futures::stream;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;
use trustify_test_context::TrustifyContext;

/// We re-ingest two versions of the same quarkus SBOM. However, as the quarkus SBOM doesn't have
/// anything in common other than the filename (which doesn't matter), these are considered two
/// different SBOMs.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn quarkus(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let sbom = SbomService::new(db.clone());
    let ingest = IngestorService::new(graph, storage);

    // ingest the first version
    let result1 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
                .await?,
        )
        .await?;

    assert_eq!(result1.document_id, "https://access.redhat.com/security/data/sbom/beta/spdx/quarkus-bom-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf");

    // ingest the second version
    let result2 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("quarkus/v2/quarkus-bom-2.13.8.Final-redhat-00004.json")
                .await?,
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

    assert_eq!(sbom1.head.name, "quarkus-bom");
    assert_eq!(sbom2.head.name, "quarkus-bom-2.13.8.Final-redhat-00004");
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

/// Re-ingest two versions of nhc. They to have the same name and mostly the same name and
/// document id/namespace. However, they still get ingested as two different SBOMs.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn nhc(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let sbom = SbomService::new(db.clone());
    let ingest = IngestorService::new(graph, storage);

    // ingest the first version
    let result1 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result1.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
    );

    // ingest the second version
    let result2 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("nhc/v2/nhc-0.4.z.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result2.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
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

    // both sboms have the same name

    assert_eq!(sbom1.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom2.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom1.described_by.len(), 1);
    assert_eq!(sbom2.described_by.len(), 1);

    // clear the ID as that one will be different

    sbom1.described_by[0].id = "".into();
    sbom2.described_by[0].id = "".into();

    assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

    // done

    Ok(())
}

/// Re-ingest the same version of nhc twice.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn nhc_same(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let sbom = SbomService::new(db.clone());
    let ingest = IngestorService::new(graph, storage);

    // ingest the first version

    let result1 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result1.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
    );

    // ingest the same version again

    let result2 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result2.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
    );

    // now start testing

    // in this case, we get the same ID, as the digest of the content is the same

    assert_eq!(result1.id, result2.id);

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

    // both sboms have the same name

    assert_eq!(sbom1.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom2.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom1.described_by.len(), 1);
    assert_eq!(sbom2.described_by.len(), 1);

    // clear the ID as that one will be different

    sbom1.described_by[0].id = "".into();
    sbom2.described_by[0].id = "".into();

    assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

    // done

    Ok(())
}

/// Re-ingest the same version of nhc twice, but reformat the second one.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn nhc_same_content(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let sbom = SbomService::new(db.clone());
    let ingest = IngestorService::new(graph, storage);

    // ingest the first version

    let result1 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("nhc/v1/nhc-0.4.z.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result1.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
    );

    // ingest the second version

    let result2 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            stream::once({
                // re-serialize file (non-pretty)
                let json: Value =
                    serde_json::from_slice(&ctx.document_bytes("nhc/v1/nhc-0.4.z.json.xz").await?)?;

                let result = serde_json::to_vec(&json).map(Bytes::from);

                async { result }
            }),
        )
        .await?;

    assert_eq!(
        result2.document_id,
        "https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8"
    );

    // now start testing

    // in this case, we get a different ID, as the digest doesn't match

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

    // both sboms have the same name

    assert_eq!(sbom1.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom2.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom1.described_by.len(), 1);
    assert_eq!(sbom2.described_by.len(), 1);

    // clear the ID as that one will be different

    sbom1.described_by[0].id = "".into();
    sbom2.described_by[0].id = "".into();

    assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

    // done

    Ok(())
}

/// Run syft twice on the same container.
///
/// This should be the same SBOM, as it's built from exactly the same container. However, conforming
/// to the SPDX spec, the document gets a new "document namespace".
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn syft_rerun(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let sbom = SbomService::new(db.clone());
    let ingest = IngestorService::new(graph, storage);

    // ingest the first version

    let result1 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("syft-ubi-example/v1.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result1.document_id,
        "https://anchore.com/syft/image/registry.access.redhat.com/ubi9/ubi-f41e17d4-e739-4d33-ab2e-48c95b856220"
    );

    // ingest the second version

    let result2 = ingest
        .ingest(
            ("source", "test"),
            None,
            Format::SPDX,
            ctx.document_stream("syft-ubi-example/v2.json.xz").await?,
        )
        .await?;

    assert_eq!(
        result2.document_id,
        "https://anchore.com/syft/image/registry.access.redhat.com/ubi9/ubi-768a701e-12fb-4ed1-a03b-463b784b01bf"
    );

    // now start testing

    // in this case, we get the same ID, as the digest of the content is the same

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

    // both sboms have the same name

    assert_eq!(sbom1.head.name, "registry.access.redhat.com/ubi9/ubi");
    assert_eq!(sbom2.head.name, "registry.access.redhat.com/ubi9/ubi");
    assert_eq!(sbom1.described_by.len(), 1);
    assert_eq!(sbom2.described_by.len(), 1);

    // clear the ID as that one will be different

    sbom1.described_by[0].id = "".into();
    sbom2.described_by[0].id = "".into();

    assert_eq!(sbom1.described_by[0], sbom2.described_by[0]);

    // done

    Ok(())
}
