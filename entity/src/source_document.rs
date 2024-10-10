use sea_orm::entity::prelude::*;
use sea_orm::JsonValue;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "source_document")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub sha256: String,
    pub sha384: String,
    pub sha512: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub meta: JsonValue,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
