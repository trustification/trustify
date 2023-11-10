use crate::advisory_cve;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cve")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub identifier: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::advisory_cve::Entity")]
    AdvisoryCves,
}

impl Related<advisory_cve::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AdvisoryCves.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
