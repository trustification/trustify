use crate::sbom_describes_package;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub location: String,
    pub sha256: String,
    pub document_id: String,

    pub title: Option<String>,
    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::sbom_describes_package::Entity")]
    DescribesPackage,
}

impl Related<sbom_describes_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DescribesPackage.def()
    }
}

/*
impl Related<sbom_dependency::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageDependencies.def()
    }
}

 */

impl ActiveModelBehavior for ActiveModel {}
