use crate::{advisory, package_version_range, sbom_dependency};
use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "affected_package_version_range")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub advisory_id: i32,
    pub package_version_range_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package_version_range::Entity",
        from = "super::affected_package_version_range::Column::PackageVersionRangeId"
        to = "super::package_version_range::Column::Id")]
    PackageVersionRange,
    #[sea_orm(
        belongs_to = "super::advisory::Entity",
        from = "super::affected_package_version_range::Column::AdvisoryId"
        to = "super::advisory::Column::Id")]
    Advisory,
}

impl Related<package_version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersionRange.def()
    }
}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
