use crate::signature_type::SignatureType;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "trust_anchor")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    pub revision: Uuid,

    pub disabled: bool,
    pub description: String,

    pub r#type: SignatureType,
    pub payload: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
