use sea_orm::entity::prelude::*;
use sea_orm::{FromJsonQueryResult, FromQueryResult};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "qualified_package")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub package_version_id: Uuid,
    pub qualifiers: Qualifiers,
}

#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, FromJsonQueryResult,
)]
pub struct Qualifiers(pub BTreeMap<String, String>);

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package_version::Entity",
        from = "super::qualified_package::Column::PackageVersionId"
        to = "super::package_version::Column::Id"
    )]
    PackageVersion,
    #[sea_orm(
        belongs_to = "super::sbom_package_purl_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_purl_ref::Column::QualifiedPackageId"
    )]
    SbomPackage,
}

impl Related<super::package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersion.def()
    }
}

impl Related<super::sbom_package_purl_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(FromQueryResult, Debug)]
pub struct PackageType {
    pub package_type: String,
}

#[derive(FromQueryResult, Debug)]
pub struct PackageNamespace {
    pub package_namespace: String,
}
