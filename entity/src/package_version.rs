use sea_orm::entity::prelude::*;
use sea_orm::FromQueryResult;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub package_id: Uuid,
    pub version: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package::Entity",
        from = "super::package_version::Column::PackageId"
        to = "super::package::Column::Id")]
    Package,
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
