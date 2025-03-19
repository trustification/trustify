use sea_orm::{FromJsonQueryResult, FromQueryResult, entity::prelude::*};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "qualified_purl")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub versioned_purl_id: Uuid,
    pub qualifiers: Qualifiers,
    pub purl: String,
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, FromJsonQueryResult,
)]
pub struct Qualifiers(pub BTreeMap<String, String>);

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::versioned_purl::Entity",
        from = "super::qualified_purl::Column::VersionedPurlId"
        to = "super::versioned_purl::Column::Id"
    )]
    VersionedPurl,
    #[sea_orm(
        belongs_to = "super::sbom_package_purl_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_purl_ref::Column::QualifiedPurlId"
    )]
    SbomPackage,
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionedPurl.def()
    }
}

impl Related<super::sbom_package_purl_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        super::versioned_purl::Relation::BasePurl.def()
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
