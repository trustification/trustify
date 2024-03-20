use crate::sbom;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_describes_cpe")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: i32,
    #[sea_orm(primary_key)]
    pub cpe_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
    belongs_to = "super::sbom::Entity",
    from = "super::sbom_describes_cpe::Column::SbomId"
    to = "super::sbom::Column::Id")]
    Sbom,
    //#[sea_orm(
    //belongs_to = "super::sbom::Entity",
    //from = "super::sbom_describes_cpe::Column::CpeId"
    //to = "super::cpe::Column::Id")]
    //Cpe,
}

impl Related<sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

/*
impl Related<cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cpe.def()
    }
}

 */

impl ActiveModelBehavior for ActiveModel {}
