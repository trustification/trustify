use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "importer_report")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub importer: String,

    pub creation: time::OffsetDateTime,
    pub error: Option<String>,

    pub report: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::importer::Entity",
        from = "Column::Importer",
        to = "super::importer::Column::Name"
    )]
    Importer,
}

impl Related<super::importer::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Importer.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
