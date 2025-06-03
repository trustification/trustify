use crate::{advisory, product};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[cfg_attr(feature = "async-graphql", derive(async_graphql::SimpleObject))]
#[cfg_attr(
    feature = "async-graphql",
    graphql(concrete(name = "Organization", params()))
)]
#[sea_orm(table_name = "organization")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub name: String,
    pub cpe_key: Option<String>,
    pub website: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<advisory::Entity> for Entity {
    fn to() -> RelationDef {
        super::advisory::Relation::Issuer.def().rev()
    }
}

impl Related<product::Entity> for Entity {
    fn to() -> RelationDef {
        super::product::Relation::Vendor.def().rev()
    }
}

impl ActiveModelBehavior for ActiveModel {}
