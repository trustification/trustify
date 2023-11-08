use crate::{package, sbom};
use sea_orm::entity::prelude::*;
use sea_orm::LinkDef;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_describes_package")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: i32,
    #[sea_orm(primary_key)]
    pub package_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "super::sbom_describes_package::Column::SbomId"
        to = "super::sbom::Column::Id")]
    Sbom,

    #[sea_orm(
    belongs_to = "super::package::Entity",
    from = "super::sbom_describes_package::Column::PackageId"
    to = "super::package::Column::Id")]
    Package,
}

impl Related<sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
