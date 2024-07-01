use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

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
    #[sea_orm(has_many = "super::package_version::Entity")]
    PackageVersions,

    #[sea_orm(has_many = "super::qualified_package::Entity")]
    QualifiedPackages,

    #[sea_orm(has_many = "super::package_status::Entity")]
    PackageStatus,

    #[sea_orm(has_many = "super::package_status::Entity")]
    VersionRange,
}

impl Related<super::package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersions.def()
    }
}

impl Related<super::qualified_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::QualifiedPackages.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::package_version::Relation::Package.def().rev())
    }
}

impl Related<super::package_status::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageStatus.def()
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
