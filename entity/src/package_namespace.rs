use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_namespace")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub namespace: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::package::Entity")]
    Packages,
    #[sea_orm(has_many = "super::package_type::Entity")]
    Types,
}

impl Related<super::package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Packages.def()
    }
}

impl Related<super::package_type::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Types.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
