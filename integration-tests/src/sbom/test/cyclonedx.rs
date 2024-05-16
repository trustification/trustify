use crate::sbom::test::{test_with_cyclonedx, WithContext};
use test_context::test_context;
use test_log::test;
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::Transactional;
use trustify_common::model::Paginated;
use trustify_module_fetch::model::sbom::SbomPackage;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_parse_cyclonedx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_cyclonedx(
        ctx,
        "zookeeper-3.9.2-cyclonedx.json",
        |WithContext { fetch, sbom, .. }| async move {
            let described = fetch
                .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                .await?;

            assert_eq!(
                described.items,
                vec![SbomPackage {
                    id: "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string(),
                    name: "zookeeper".to_string(),
                    purl: vec![
                        "pkg://maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string()
                    ],
                    cpe: vec![],
                }]
            );

            let packages = fetch
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

            log::info!("{:?}", packages);

            assert_eq!(41, packages.total);

            Ok(())
        },
    )
    .await
}
