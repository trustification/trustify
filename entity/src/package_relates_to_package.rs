use crate::relationship::Relationship;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_relates_to_package")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub left_package_id: i32,
    #[sea_orm(primary_key)]
    pub relationship: Relationship,
    #[sea_orm(primary_key)]
    pub right_package_id: i32,
    #[sea_orm(primary_key)]
    pub sbom_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    //#[sea_orm(has_many = "super::package_qualifier::Entity")]
    //PackageQualifiers,
    //#[sea_orm(has_many = "super::sbom::Entity")]
    //SbomDependents,
}

impl ActiveModelBehavior for ActiveModel {}
