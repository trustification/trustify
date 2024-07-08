mod helpers;
use helpers::{test_with_cyclonedx, WithContext};
use test_context::test_context;
use test_log::test;
use trustify_common::db::Transactional;
use trustify_common::model::Paginated;
use trustify_module_fundamental::sbom::model::SbomPackage;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_parse_cyclonedx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_cyclonedx(
        ctx,
        "zookeeper-3.9.2-cyclonedx.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), Transactional::None)
                .await?;

            assert_eq!(
                described.items,
                vec![SbomPackage {
                    id: "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string(),
                    name: "zookeeper".to_string(),
                    version: Some("3.9.2".to_string()),
                    purl: vec![
                        "pkg://maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string()
                    ],
                    cpe: vec![],
                }]
            );

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
