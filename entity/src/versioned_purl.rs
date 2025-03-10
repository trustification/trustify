use sea_orm::{FromQueryResult, entity::prelude::*};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "versioned_purl")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub base_purl_id: Uuid,
    pub version: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::base_purl::Entity",
        from = "super::versioned_purl::Column::BasePurlId"
        to = "super::base_purl::Column::Id")]
    BasePurl,

    #[sea_orm(has_many = "super::qualified_purl::Entity")]
    QualifiedPurl,

    #[sea_orm(has_many = "super::version_range::Entity")]
    VersionRange,

    #[sea_orm(has_many = "super::purl_status::Entity")]
    PurlStatus,
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BasePurl.def()
    }
}

impl Related<super::qualified_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::QualifiedPurl.def()
    }
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }

    fn via() -> Option<RelationDef> {
        Some(Relation::PurlStatus.def())
    }
}

impl Related<super::purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PurlStatus.def()
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
