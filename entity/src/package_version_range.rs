use crate::sbom_contains_package;
use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_version_range")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub package_id: i32,
    pub start: String,
    pub end: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package::Entity",
        from = "super::package_version_range::Column::PackageId"
        to = "super::package::Column::Id")]
    Package,
    //#[sea_orm(has_many = "super::package_qualifier::Entity")]
    //PackageQualifiers,
    //#[sea_orm(has_many = "super::sbom::Entity")]
    //SbomDependents,
}

impl Related<super::package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

/*
impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        //Relation::SbomDependents.def()
        sbom_dependency::Relation::Sbom.def()
    }

    fn via() -> Option<RelationDef> {
        Some(sbom_dependency::Relation::Sbom.def().rev())
    }
}

 */

impl ActiveModelBehavior for ActiveModel {}

#[derive(FromQueryResult, Debug)]
pub struct PackageType {
    pub package_type: String,
}

#[derive(FromQueryResult, Debug)]
pub struct PackageNamespace {
    pub package_namespace: String,
}
