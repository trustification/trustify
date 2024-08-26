use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "weakness")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    pub description: Option<String>,
    pub extended_description: Option<String>,
    pub child_of: Option<Vec<String>>,
    pub parent_of: Option<Vec<String>>,
    pub starts_with: Option<Vec<String>>,
    pub can_follow: Option<Vec<String>>,
    pub can_precede: Option<Vec<String>>,
    pub required_by: Option<Vec<String>>,
    pub requires: Option<Vec<String>>,
    pub can_also_be: Option<Vec<String>>,
    pub peer_of: Option<Vec<String>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
