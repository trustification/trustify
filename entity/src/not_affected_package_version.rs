use crate::{advisory, package_version, vulnerability};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "not_affected_package_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub advisory_id: i32,
    pub vulnerability_id: i32,
    pub package_version_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package_version::Entity",
        from = "super::not_affected_package_version::Column::PackageVersionId"
        to = "super::package_version::Column::Id")]
    PackageVersion,
    #[sea_orm(
        belongs_to = "super::advisory::Entity",
        from = "super::not_affected_package_version::Column::AdvisoryId"
        to = "super::advisory::Column::Id")]
    Advisory,
    #[sea_orm(
        belongs_to = "super::vulnerability::Entity",
        from = "super::not_affected_package_version::Column::VulnerabilityId"
        to = "super::vulnerability::Column::Id")]
    Vulnerability,
}

impl Related<package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersion.def()
    }
}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<vulnerability::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
