use crate::relationship::Relationship;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_relates_to_package")]
pub struct Model {
    // the SBOM the relationship belongs to
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    // TODO: allow for external sbom namespace
    #[sea_orm(primary_key)]
    pub left_node_id: String,
    #[sea_orm(primary_key)]
    pub relationship: Relationship,
    // TODO: allow for external sbom namespace
    #[sea_orm(primary_key)]
    pub right_node_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_node::Entity",
        from = "(Column::SbomId, Column::LeftNodeId)",
        to = "(super::sbom_node::Column::SbomId, super::sbom_node::Column::NodeId)"
    )]
    Left,
    #[sea_orm(
        belongs_to = "super::sbom_node::Entity",
        from = "(Column::SbomId, Column::RightNodeId)",
        to = "(super::sbom_node::Column::SbomId, super::sbom_node::Column::NodeId)"
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
