use sea_orm::{FromQueryResult, entity::prelude::*};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "base_purl")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub r#type: String,
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::versioned_purl::Entity")]
    VersionedPurls,

    #[sea_orm(has_many = "super::qualified_purl::Entity")]
    QualifiedPurls,

    #[sea_orm(has_many = "super::purl_status::Entity")]
    PurlStatus,

    #[sea_orm(has_many = "super::purl_status::Entity")]
    VersionRange,
}

impl Related<super::versioned_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionedPurls.def()
    }
}

impl Related<super::qualified_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::QualifiedPurls.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::versioned_purl::Relation::BasePurl.def().rev())
    }
}

impl Related<super::purl_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PurlStatus.def()
    }
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
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
