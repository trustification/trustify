use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "source_document")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub sha256: String,
    pub sha384: String,
    pub sha512: String,
    pub size: i64,
    pub ingested: time::OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::source_document_signature::Entity")]
    Signature,
}

impl ActiveModelBehavior for ActiveModel {}
