use crate::{advisory, package_version_range, sbom_dependency};
use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "fixed_package_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub advisory_id: i32,
    pub package_version_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package_version::Entity",
        from = "super::fixed_package_version::Column::PackageVersionId"
        to = "super::package_version::Column::Id")]
    PackageVersion,
    #[sea_orm(
        belongs_to = "super::advisory::Entity",
        from = "super::fixed_package_version::Column::AdvisoryId"
        to = "super::advisory::Column::Id")]
    Advisory,
}

impl Related<package_version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersion.def()
    }
}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
