use crate::{advisory, cve, package, sbom_dependency};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "advisory_cve")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub advisory_id: i32,
    #[sea_orm(primary_key)]
    pub cve_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::advisory::Entity",
        from = "super::advisory_cve::Column::AdvisoryId"
        to = "super::advisory::Column::Id")]
    Advisory,
    #[sea_orm(
        belongs_to = "super::cve::Entity",
        from = "super::advisory_cve::Column::CveId"
        to = "super::cve::Column::Id")]
    Cve,
}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Advisory.def()
    }
}

impl Related<cve::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cve.def()
    }
}
impl ActiveModelBehavior for ActiveModel {}
