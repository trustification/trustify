#![allow(clippy::expect_used)]
use sea_orm::{EntityTrait, FromQueryResult, QuerySelect, RelationTrait, query::*};
use test_context::test_context;
use test_log::test;
use trustify_entity::{sbom_node, sbom_package};
use trustify_test_context::TrustifyContext;

#[derive(Debug, FromQueryResult)]
pub struct SbomPackageBase {
    pub component_group: Option<String>,
    pub component_version: Option<String>,
    pub package_name: Option<String>,
}
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_add_group_field_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let result: Vec<SbomPackageBase> = sbom_package::Entity::find()
        .join(JoinType::Join, sbom_package::Relation::Node.def())
        .select_only()
        .column_as(sbom_package::Column::Group, "component_group")
        .column_as(sbom_package::Column::Version, "component_version")
        .column_as(sbom_node::Column::Name, "package_name")
        .into_model::<SbomPackageBase>()
        .all(&ctx.db)
        .await?;

    for r in result {
        assert_eq!(r.component_group, None)
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_add_group_field_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?;

    let result: Vec<SbomPackageBase> = sbom_package::Entity::find()
        .join(JoinType::Join, sbom_package::Relation::Node.def())
        .select_only()
        .column_as(sbom_package::Column::Group, "component_group")
        .column_as(sbom_package::Column::Version, "component_version")
        .column_as(sbom_node::Column::Name, "package_name")
        .into_model::<SbomPackageBase>()
        .all(&ctx.db)
        .await?;

    for r in result {
        if r.package_name.as_deref() == Some("spring-boot-starter-actuator") {
            assert_eq!(
                r.component_group.as_deref(),
                Some("org.springframework.boot")
            );
            assert_eq!(r.component_version.as_deref(), Some("3.3.4"));
        }
        if r.package_name.as_deref() == Some("logback-classic") {
            assert_eq!(r.component_group.as_deref(), Some("ch.qos.logback"));
            assert_eq!(r.component_version.as_deref(), Some("1.5.8"));
        }
    }
    Ok(())
}
