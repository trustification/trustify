use crate::sbom;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_describes_cpe22")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: i32,
    #[sea_orm(primary_key)]
    pub cpe22_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
    belongs_to = "super::sbom::Entity",
    from = "super::sbom_describes_cpe22::Column::SbomId"
    to = "super::sbom::Column::Id")]
    Sbom,
    //#[sea_orm(
    //belongs_to = "super::sbom::Entity",
    //from = "super::sbom_describes_cpe22::Column::Cpe22Id"
    //to = "super::cpe22::Column::Id")]
    //Cpe22,
}

impl Related<sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

/*
impl Related<cpe22::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cpe22.def()
    }
}

 */

impl ActiveModelBehavior for ActiveModel {}
