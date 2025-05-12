use crate::signature_type::SignatureType;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "source_document_signature")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub document_id: Uuid,
    pub r#type: SignatureType,
    pub payload: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::source_document::Entity",
        from = "Column::DocumentId",
        to = "super::source_document::Column::Id"
    )]
    SourceDocument,
}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::source_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SourceDocument.def()
    }
}
