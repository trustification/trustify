
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_type")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub r#type: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::package_namespace::Entity")]
    Namespace,
    #[sea_orm(has_many = "super::package_namespace::Entity")]
    Package,
}

impl Related<super::package_namespace::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Namespace.def()
    }
}

impl Related<super::package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
