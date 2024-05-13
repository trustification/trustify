use crate::relationship::Relationship;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_relates_to_package")]
pub struct Model {
    // the SBOM the relationship belongs to
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    // TODO: change to sbom package
    #[sea_orm(primary_key)]
    pub left_package_id: Uuid,
    #[sea_orm(primary_key)]
    pub relationship: Relationship,
    // TODO: change to sbom package
    #[sea_orm(primary_key)]
    pub right_package_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::qualified_package::Entity",
        from = "Column::LeftPackageId",
        to = "super::qualified_package::Column::Id"
    )]
    Left,
    #[sea_orm(
        belongs_to = "super::qualified_package::Entity",
        from = "Column::RightPackageId",
        to = "super::qualified_package::Column::Id"
    )]
    Right,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
}

impl ActiveModelBehavior for ActiveModel {}
