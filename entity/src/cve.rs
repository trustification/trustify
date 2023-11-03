use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cve")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::cve_affected::Entity")]
    Affected,
}

impl Related<super::cve_affected::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Affected.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
