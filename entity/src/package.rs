use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub r#type: String,
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::package_version::Entity")]
    PackageVersions,
}

impl Related<super::package_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageVersions.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(FromQueryResult, Debug)]
pub struct PackageType {
    pub package_type: String,
}

#[derive(FromQueryResult, Debug)]
pub struct PackageNamespace {
    pub package_namespace: String,
}
