use super::*;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::model::Paginated;
use trustify_module_fundamental::sbom::model::SbomPackage;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn ingest_spdx_medium(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "openshift-container-storage-4.8.z.json.xz",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), &ctx.db)
                .await?;

            log::debug!("{:#?}", described);
            assert_eq!(1, described.items.len());
            assert_eq!(
                described.items[0],
                SbomPackage {
                    id: "SPDXRef-5fbf9e8d-2f8f-4cfe-a145-b69a1f7d73cc".to_string(),
                    name: "RHEL-8-RHOCS-4.8".to_string(),
                    version: Some("4.8.z".to_string()),
                    purl: vec![],
                    cpe: vec!["cpe:/a:redhat:openshift_container_storage:4.8:*:el8:*".into()],
                }
            );

            let packages = service
                .fetch_sbom_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Paginated {
                        offset: 0,
                        limit: 1,
                    },
                    &ctx.db,
                )
                .await?;
            assert_eq!(1, packages.items.len());
            assert_eq!(7994, packages.total);

            Ok(())
        },
    )
    .await
}

// ignore because it's a slow slow slow test.
#[test_context(TrustifyContext)]
#[ignore]
#[test(tokio::test)]
async fn ingest_spdx_large(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "openshift-4.13.json.xz",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), &ctx.db)
                .await?;
            log::debug!("{:#?}", described);
            assert_eq!(1, described.items.len());

            let first = &described.items[0];
            assert_eq!(3, first.cpe.len());

            Ok(())
        },
    )
    .await
}

/// A test having a lot of CPEs to ingest
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn ingest_spdx_medium_cpes(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "rhel-br-9.2.0.json.xz",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Default::default(), &ctx.db)
                .await?;

            log::debug!("{:#?}", described);
            assert_eq!(1, described.items.len());
            assert_eq!(
                described.items[0],
                SbomPackage {
                    id: "SPDXRef-59713547-8cb2-4cf4-a310-1e28c7a7b35a".to_string(),
                    name: "RHEL-BR-9.2.0".to_string(),
                    version: Some("9.2.0".to_string()),
                    purl: vec![],
                    cpe: vec![],
                }
            );

            let packages = service
                .fetch_sbom_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Paginated {
                        offset: 0,
                        limit: 1,
                    },
                    &ctx.db,
                )
                .await?;
            assert_eq!(1, packages.items.len());
            assert_eq!(50668, packages.total);

            Ok(())
        },
    )
    .await
}
