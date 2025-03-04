#![allow(clippy::all)]
use sea_orm::FromQueryResult;
use sea_orm::query::*;
use sea_orm::{EntityTrait, QuerySelect, RelationTrait};
// use sea_orm::{
//     Condition, DatabaseConnection, DbBackend, EntityTrait, QueryFilter, QuerySelect, RelationTrait,
//     sea_query,
// };
use test_context::test_context;
use test_log::test;
use trustify_entity::{license, sbom, sbom_node, sbom_package, sbom_package_license};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

// #[derive(Debug, FromQueryResult)]
// pub struct SbomLicenseBase {
//     pub sbom_name: Option<String>,
//     pub sbom_namespace: Option<String>,
//     pub component_group: Option<String>,
//     pub component_version: Option<String>,
//     pub node_id: String,
//     pub sbom_id: Uuid,
//     pub package_name: String,
//     pub version: String,
//     pub purl: serde_json::Value,
//     pub cpe: Option<Vec<String>>,
//     pub text: Option<String>,
//     pub spdx_licenses: Option<Vec<String>>,
//     pub spdx_license_exceptions: Option<Vec<String>>,
// }

#[derive(Debug, FromQueryResult)]
#[allow(dead_code)]
pub struct SbomPackageLicenseBase {
    pub sbom_name: Option<String>,
    pub sbom_namespace: Option<String>,
    pub component_group: Option<String>,
    pub component_version: Option<String>,
    pub node_id: String,
    pub sbom_id: Uuid,
    pub package_name: String,
    pub version: String,
    pub license_text: Option<String>,
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    let sbom_license_base: Vec<SbomPackageLicenseBase> = sbom::Entity::find()
        .join(JoinType::LeftJoin, sbom::Relation::Packages.def())
        .join(JoinType::Join, sbom_package::Relation::Node.def())
        .join(
            JoinType::LeftJoin,
            sbom_package::Relation::PackageLicense.def(),
        )
        .join(
            JoinType::LeftJoin,
            sbom_package_license::Relation::License.def(),
        )
        .select_only()
        .column_as(sbom::Column::SbomId, "sbom_id")
        .column_as(sbom::Column::DocumentId, "sbom_namespace")
        .column_as(sbom_package::Column::NodeId, "node_id")
        .column_as(sbom_package::Column::Version, "version")
        .column_as(sbom_node::Column::Name, "package_name")
        .column_as(license::Column::Text, "license_text")
        .into_model::<SbomPackageLicenseBase>()
        .all(&ctx.db)
        .await?;

    for s in sbom_license_base {
        println!("{:?}", s);
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx
        .ingest_document("cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json")
        .await?;
    let sbom_license_base: Vec<SbomPackageLicenseBase> = sbom::Entity::find()
        .join(JoinType::LeftJoin, sbom::Relation::Packages.def())
        .join(JoinType::Join, sbom_package::Relation::Node.def())
        .join(
            JoinType::LeftJoin,
            sbom_package::Relation::PackageLicense.def(),
        )
        .join(
            JoinType::LeftJoin,
            sbom_package_license::Relation::License.def(),
        )
        .select_only()
        .column_as(sbom::Column::SbomId, "sbom_id")
        .column_as(sbom::Column::DocumentId, "sbom_namespace")
        .column_as(sbom_package::Column::NodeId, "node_id")
        .column_as(sbom_package::Column::Version, "version")
        .column_as(sbom_node::Column::Name, "package_name")
        .column_as(license::Column::Text, "license_text")
        .into_model::<SbomPackageLicenseBase>()
        .all(&ctx.db)
        .await?;
    for a in sbom_license_base {
        println!("{:?}", a);
    }
    Ok(())
}
