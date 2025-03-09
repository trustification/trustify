// #![allow(clippy::all)]
// use sea_orm::FromQueryResult;
// use sea_orm::query::*;
// use sea_orm::{ColumnTrait, EntityTrait, QuerySelect, RelationTrait, SelectColumns};
// // use sea_orm::{
// //     Condition, DatabaseConnection, DbBackend, EntityTrait, QueryFilter, QuerySelect, RelationTrait,
// //     sea_query,
// // };
// use test_context::test_context;
// use test_log::test;
// use trustify_common::id::TrySelectForId;
// use trustify_entity::qualified_purl::CanonicalPurl;
// use trustify_entity::{
//     cpe, license, qualified_purl, sbom, sbom_node, sbom_package, sbom_package_cpe_ref,
//     sbom_package_license, sbom_package_purl_ref,
// };
// use trustify_test_context::TrustifyContext;
// use uuid::Uuid;
//
// #[derive(Debug, Clone, Default)]
// pub struct SbomPackage {
//     /// Package name
//     pub name: String,
//     /// Package version
//     pub version: Option<String>,
//     /// package package URL
//     pub purl: Vec<Purl>,
//     pub other_reference: Vec<Cpe>,
//     /// List of all package license
//     pub license_text: Option<String>,
// }
//
// #[derive(Debug, Clone, FromQueryResult)]
// pub struct Sbom {
//     pub sbom_id: Uuid,
//     pub node_id: String,
//     pub sbom_namespace: String,
// }
//
// #[derive(Debug, Clone, FromQueryResult)]
// pub struct Purl {
//     pub purl: CanonicalPurl,
// }
//
// #[derive(Debug, Clone, FromQueryResult)]
// pub struct Cpe {
//     pub part: Option<String>,
//     pub vendor: Option<String>,
//     pub product: Option<String>,
//     pub version: Option<String>,
//     pub update: Option<String>,
//     pub edition: Option<String>,
//     pub language: Option<String>,
// }
//
// #[derive(Debug, Clone, FromQueryResult)]
// pub struct SbomPackageLicenseBase {
//     pub sbom_name: Option<String>,
//     pub sbom_namespace: Option<String>,
//     pub component_group: Option<String>,
//     pub component_version: Option<String>,
//     pub node_id: String,
//     pub sbom_id: Uuid,
//     pub package_name: String,
//     pub license_text: Option<String>,
// }
//
// #[derive(Debug, Clone, Default)]
// pub struct SbomLicense {
//     pub sbom_name: Option<String>,
//     pub sbom_namespace: Option<String>,
//     pub packages: Vec<SbomPackage>,
// }
//
// #[derive(Debug, Clone, Default, FromQueryResult)]
// pub struct SbomNodeInfo {
//     pub sbom_name: Option<String>,
//     pub node_id: String,
//     pub component_group: Option<String>,
//     pub component_version: Option<String>,
// }
//
// #[derive(Debug, Clone, Default, FromQueryResult)]
// pub struct SbomName {
//     pub sbom_name: String,
// }
//
// #[test_context(TrustifyContext)]
// #[test(tokio::test)]
// async fn test_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
//     let _result = ctx
//         .ingest_document("cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json")
//         .await?;
//
//     let result_sbom: Option<Sbom> = sbom::Entity::find()
//         .column_as(sbom::Column::SbomId, "sbom_id")
//         .column_as(sbom::Column::DocumentId, "sbom_namespace")
//         .column_as(sbom::Column::NodeId, "node_id")
//         .into_model::<Sbom>()
//         .one(&ctx.db)
//         .await?;
//     println!("{:?}", result_sbom.clone());
//
//     if let Some(id) = result_sbom {
//         let sbom_name: Option<SbomName> = sbom_node::Entity::find()
//             .filter(Condition::all().add(sbom_node::Column::NodeId.eq(id.node_id.clone())))
//             .column_as(sbom_node::Column::Name, "sbom_name")
//             .into_model::<SbomName>()
//             .one(&ctx.db)
//             .await?;
//
//         let mut sbom_licenses = SbomLicense::default();
//         let sbom_license_base: Vec<SbomPackageLicenseBase> = sbom::Entity::find()
//             .try_filter(trustify_common::id::Id::Uuid(id.sbom_id))?
//             .join(JoinType::LeftJoin, sbom::Relation::Packages.def())
//             .join(JoinType::Join, sbom_package::Relation::Node.def())
//             .join(
//                 JoinType::LeftJoin,
//                 sbom_package::Relation::PackageLicense.def(),
//             )
//             .join(
//                 JoinType::LeftJoin,
//                 sbom_package_license::Relation::License.def(),
//             )
//             .select_only()
//             .column_as(sbom::Column::SbomId, "sbom_id")
//             .column_as(sbom::Column::DocumentId, "sbom_namespace")
//             .column_as(sbom_package::Column::NodeId, "node_id")
//             .column_as(sbom_package::Column::Group, "component_group")
//             .column_as(sbom_package::Column::Version, "component_version")
//             .column_as(sbom_node::Column::Name, "package_name")
//             .column_as(license::Column::Text, "license_text")
//             .into_model::<SbomPackageLicenseBase>()
//             .all(&ctx.db)
//             .await?;
//
//         let mut sbom_package_list = Vec::new();
//         for sl in sbom_license_base {
//             let result_purl: Vec<Purl> = sbom_package_purl_ref::Entity::find()
//                 .join(JoinType::Join, sbom_package_purl_ref::Relation::Purl.def())
//                 .filter(
//                     Condition::all()
//                         .add(sbom_package_purl_ref::Column::NodeId.eq(sl.node_id.clone()))
//                         .add(sbom_package_purl_ref::Column::SbomId.eq(sl.sbom_id.clone())),
//                 )
//                 .select_only()
//                 .column_as(qualified_purl::Column::Purl, "purl")
//                 .into_model::<Purl>()
//                 .all(&ctx.db)
//                 .await?;
//             let result_cpe: Vec<Cpe> = sbom_package_cpe_ref::Entity::find()
//                 .join(JoinType::Join, sbom_package_cpe_ref::Relation::Cpe.def())
//                 .filter(
//                     Condition::all()
//                         .add(sbom_package_cpe_ref::Column::NodeId.eq(sl.node_id.clone()))
//                         .add(sbom_package_cpe_ref::Column::SbomId.eq(sl.sbom_id.clone())),
//                 )
//                 .select_only()
//                 .column_as(cpe::Column::Part, "cpe")
//                 .column_as(cpe::Column::Vendor, "vendor")
//                 .column_as(cpe::Column::Product, "product")
//                 .column_as(cpe::Column::Version, "version")
//                 .column_as(cpe::Column::Update, "update")
//                 .column_as(cpe::Column::Edition, "edition")
//                 .column_as(cpe::Column::Language, "language")
//                 .into_model::<Cpe>()
//                 .all(&ctx.db)
//                 .await?;
//
//             let sbom_package = SbomPackage {
//                 name: sl.package_name,
//                 version: sl.component_version,
//                 purl: result_purl,
//                 other_reference: result_cpe,
//                 license_text: sl.license_text,
//             };
//
//             sbom_package_list.push(sbom_package);
//         }
//         let sbom_license = SbomLicense {
//             sbom_name: Some(
//                 sbom_name
//                     .unwrap_or_else(|| SbomName {
//                         sbom_name: String::default(),
//                     })
//                     .sbom_name,
//             ),
//             sbom_namespace: Some(id.sbom_namespace),
//             packages: sbom_package_list,
//         };
//
//         println!("{:?}", sbom_license);
//     }
//
//     Ok(())
// }
//
// #[test_context(TrustifyContext)]
// #[test(tokio::test)]
// async fn test_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
//     // let _result = ctx
//     //     .ingest_document("cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json")
//     //     .await?;
//     // let sbom_license_base: Vec<SbomPackageLicenseBase> = sbom::Entity::find()
//     //     .join(JoinType::LeftJoin, sbom::Relation::Packages.def())
//     //     .join(JoinType::Join, sbom_package::Relation::Node.def())
//     //     .join(
//     //         JoinType::LeftJoin,
//     //         sbom_package::Relation::PackageLicense.def(),
//     //     )
//     //     .join(
//     //         JoinType::LeftJoin,
//     //         sbom_package_license::Relation::License.def(),
//     //     )
//     //     .select_only()
//     //     .column_as(sbom::Column::SbomId, "sbom_id")
//     //     .column_as(sbom::Column::DocumentId, "sbom_namespace")
//     //     .column_as(sbom_package::Column::NodeId, "node_id")
//     //     .column_as(sbom_package::Column::Version, "version")
//     //     .column_as(sbom_node::Column::Name, "package_name")
//     //     .column_as(license::Column::Text, "license_text")
//     //     .into_model::<SbomPackageLicenseBase>()
//     //     .all(&ctx.db)
//     //     .await?;
//     // for a in sbom_license_base {
//     //     println!("{:?}", a);
//     // }
//     Ok(())
// }
