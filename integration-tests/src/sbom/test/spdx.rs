use crate::sbom::test::{test_with_spdx, WithContext};
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::{db::test::TrustifyContext, db::Transactional};
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::sbom::model::{SbomPackage, Which};

#[test_context(TrustifyContext, skip_teardown)]
#[instrument]
#[test(tokio::test)]
async fn parse_spdx_quarkus(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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
            assert_eq!(
                &SbomPackage {
                    id: "SPDXRef-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf".into(),
                    name: "quarkus-bom".into(),
                    version: Some("2.13.8.Final-redhat-00004".to_string()),
                    purl: vec![
                        "pkg://maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom".into()
                    ],
                    cpe: vec!["cpe:/a:redhat:quarkus:2.13:*:el8:*".to_string()],
                },
                first
            );

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

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_parse_spdx(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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
