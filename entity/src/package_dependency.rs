use crate::{package, package_dependency};
use sea_orm::entity::prelude::*;
use sea_orm::LinkDef;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_dependency")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub dependent_package_id: i32,
    #[sea_orm(primary_key)]
    pub dependency_package_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
    belongs_to = "super::package::Entity",
    from = "super::package_dependency::Column::DependentPackageId"
    to = "super::package::Column::Id")]
    Dependent,
    #[sea_orm(
    belongs_to = "super::package::Entity",
    from = "super::package_dependency::Column::DependencyPackageId"
    to = "super::package::Column::Id")]
    Dependency,
}

pub struct ToDependent;
pub struct ToDependency;

impl Linked for ToDependency {
    type FromEntity = package::Entity;
    type ToEntity = package::Entity;

    fn link(&self) -> Vec<LinkDef> {
        vec![Relation::Dependent.def().rev(), Relation::Dependency.def()]
    }
}

impl ActiveModelBehavior for ActiveModel {}
