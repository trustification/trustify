use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "versioned_purl")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub package_id: Uuid,
    pub version: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::base_purl::Entity",
        from = "super::versioned_purl::Column::PackageId"
        to = "super::base_purl::Column::Id")]
    Package,

    #[sea_orm(has_many = "super::qualified_purl::Entity")]
    QualifiedPackage,

    #[sea_orm(has_many = "super::version_range::Entity")]
    VersionRange,

    #[sea_orm(has_many = "super::package_status::Entity")]
    PackageStatus,
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl Related<super::qualified_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::QualifiedPackage.def()
    }
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }

    fn via() -> Option<RelationDef> {
        Some(Relation::PackageStatus.def())
    }
}

impl Related<super::package_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
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
