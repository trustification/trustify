mod cpe;

use super::*;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Transactional;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_module_fundamental::purl::model::summary::purl::PurlSummary;
use trustify_module_fundamental::purl::model::PurlHead;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_parse_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_cyclonedx(
        ctx,
        "zookeeper-3.9.2-cyclonedx.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                .await?;

            assert_eq!(1, described.items.len());

            let package = &described.items[0];

            assert_eq!(
                package.id,
                "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar"
            );
            assert_eq!(package.name, "zookeeper");
            assert_eq!(package.version, Some("3.9.2".to_string()));
            assert_eq!(1, package.purl.len());

            assert!(matches!(
                &package.purl[0],
                PurlSummary {
                    head: PurlHead {
                        purl,
                        ..
                    },
                    ..
                }
             if *purl == Purl::from_str( "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar")?));

            assert!(package.cpe.is_empty());

            /*
            assert_eq!(
                described.items,
                vec![SbomPackage {
                    id: "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string(),
                    name: "zookeeper".to_string(),
                    version: Some("3.9.2".to_string()),
                    purl: vec![SbomPackagePurl::String(
                        "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string()
                    )],
                    cpe: vec![],
                }]
            );

             */

            let packages = service
                .fetch_sbom_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Paginated {
                        offset: 0,
                        limit: 1,
                    },
                    (),
                )
                .await?;

            log::debug!("{:?}", packages);

            assert_eq!(41, packages.total);

            Ok(())
        },
    )
    .await
}

#[instrument(skip(ctx, f))]
pub async fn test_with_cyclonedx<F, Fut>(
    ctx: &TrustifyContext,
    sbom: &str,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(WithContext) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    test_with(
        ctx,
        sbom,
        |data| Ok(Bom::parse_from_json(data)?),
        |ctx, sbom, tx| Box::pin(async move { ctx.ingest_cyclonedx(sbom.clone(), &tx).await }),
        |sbom| sbom::cyclonedx::Information(sbom).into(),
        f,
    )
    .await
}
