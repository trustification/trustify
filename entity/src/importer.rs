use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "importer")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub name: String,
    pub revision: Uuid,

    pub state: State,
    pub last_change: time::OffsetDateTime,

    pub last_success: Option<time::OffsetDateTime>,
    pub last_run: Option<time::OffsetDateTime>,
    pub last_error: Option<String>,

    pub configuration: serde_json::Value,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum State {
    Waiting = 0,
    Running = 1,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::importer_report::Entity")]
    Report,
}

impl Related<super::importer_report::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Report.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
