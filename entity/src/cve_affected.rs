use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cve_affected")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub purl: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::cve::Entity",
        from = "super::cve_affected::Column::Id"
        to = "super::cve::Column::Id"
    )]
    Id,
}

impl Related<super::cve::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Id.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
