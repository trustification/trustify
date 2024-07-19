mod perf;

use super::*;
use std::convert::Infallible;
use std::str::FromStr;
use test_context::futures::stream;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::Transactional;
use trustify_common::purl::Purl;
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::purl::model::summary::purl::PurlSummary;
use trustify_module_fundamental::purl::model::PurlHead;
use trustify_module_fundamental::sbom::model::Which;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn parse_spdx_quarkus(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "quarkus-bom-2.13.8.Final-redhat-00004.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                .await?;
            log::debug!("{:#?}", described);
            assert_eq!(1, described.items.len());
            let first = &described.items[0];

            assert_eq!( first.id, "SPDXRef-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf");
            assert_eq!( first.name, "quarkus-bom");
            assert_eq!( first.version, Some("2.13.8.Final-redhat-00004".to_string()));

            assert!( matches!(
                &first.purl[0],
                PurlSummary {
                    head: PurlHead {
                        purl,
                        ..
                    },
                    ..
                }
                if *purl == Purl::from_str("pkg://maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom")?
            ));

            let contains = service
                .related_packages(
                    sbom.sbom.sbom_id,
                    Relationship::ContainedBy,
                    first,
                    Transactional::None,
                )
                .await?;

            log::debug!("{}", contains.len());

            assert!(contains.len() > 500);

            Ok(())
        },
    ).await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_parse_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "ubi9-9.2-755.1697625012.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                .await?;

            assert_eq!(1, described.total);
            let first = &described.items[0];

            let contains = service
                .fetch_related_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Default::default(),
                    Which::Right,
                    first,
                    Some(Relationship::ContainedBy),
                    (),
                )
                .await?
                .items;

            log::debug!("{}", contains.len());

            assert!(contains.len() > 500);

            Ok(())
        },
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_spdx_broken_refs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let data = document_bytes("spdx/broken-refs.json").await?;
    let (storage, _tmp) = FileSystemBackend::for_test().await?;
    let ingestor = IngestorService::new(graph, storage);
    let sbom = SbomService::new(db.clone());

    let err = ingestor
        .ingest(
            ("source", "test"),
            None,
            Format::sbom_from_bytes(&data)?,
            stream::iter([Ok::<_, Infallible>(data)]),
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

/// remove all relationships having broken references
fn fix_spdx_rels(mut spdx: SPDX) -> SPDX {
    let mut ids = spdx
        .package_information
        .iter()
        .map(|p| &p.package_spdx_identifier)
        .collect::<HashSet<_>>();

    ids.insert(&spdx.document_creation_information.spdx_identifier);

    spdx.relationships.retain(|rel| {
        let r = ids.contains(&rel.spdx_element_id) && ids.contains(&rel.related_spdx_element);
        if !r {
            log::warn!(
                "Dropping - left: {}, rel: {:?}, right: {}",
                rel.spdx_element_id,
                rel.relationship_type,
                rel.related_spdx_element
            );
        }
        r
    });

    spdx
}

#[instrument(skip(ctx, f))]
pub async fn test_with_spdx<F, Fut>(ctx: &TrustifyContext, sbom: &str, f: F) -> anyhow::Result<()>
where
    F: FnOnce(WithContext) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    test_with(
        ctx,
        sbom,
        |data| {
            let (sbom, _) = parse_spdx(&Discard, data)?;
            Ok(fix_spdx_rels(sbom))
        },
        |ctx, sbom, tx| {
            Box::pin(async move {
                ctx.ingest_spdx(sbom.clone(), &Discard, &tx).await?;
                Ok(())
            })
        },
        |sbom| sbom::spdx::Information(sbom).into(),
        f,
    )
    .await
}
