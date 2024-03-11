use crate::sbom_describes_package;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub location: String,
    pub sha256: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    //#[sea_orm(has_many = "super::package::Entity")]
    //Packages
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

/*
impl Related<package::Entity> for Entity {
    fn to() -> RelationDef {
        //Relation::PackageDependencies.def()
        sbom_dependency::Relation::Package.def()
    }

    fn via() -> Option<RelationDef> {
        Some(sbom_dependency::Relation::Package.def().rev())
    }
    //fn via() -> Option<RelationDef> {
    //Some(sbom_dependency::Relation::Package.def())
    //}
}

 */

impl ActiveModelBehavior for ActiveModel {}
