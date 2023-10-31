use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub package_type_id: i32,
    pub package_namespace_id: Option<i32>,
    pub package_name_id: i32,
    pub version: String,
}


#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::package_type::Entity")]
    PackageType,
    #[sea_orm(has_one = "super::package_namespace::Entity")]
    PackageNamespace,
    #[sea_orm(has_many = "super::package_qualifier::Entity")]
    PackageQualifiers
}

impl Related<super::package_type::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageType.def()
    }
}

impl Related<super::package_namespace::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageNamespace.def()
    }
}

impl Related<super::package_qualifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageQualifiers.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

