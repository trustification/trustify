use crate::{package, sbom};
use sea_orm::entity::prelude::*;
use sea_orm::LinkDef;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_describes_cpe")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: i32,
    #[sea_orm(primary_key)]
    pub cpe: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "super::sbom_describes_cpe::Column::SbomId"
        to = "super::sbom::Column::Id")]
    Sbom,
}

impl Related<sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
