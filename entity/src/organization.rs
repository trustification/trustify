use crate::{advisory, product};
use async_graphql::*;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, SimpleObject)]
#[graphql(concrete(name = "Organization", params()))]
#[sea_orm(table_name = "organization")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub cpe_key: Option<String>,
    pub website: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        super::advisory::Relation::Organization.def().rev()
    }
}

impl Related<product::Entity> for Entity {
    fn to() -> RelationDef {
        super::product::Relation::Vendor.def().rev()
    }
}

impl ActiveModelBehavior for ActiveModel {}
