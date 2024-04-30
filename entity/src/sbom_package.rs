use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_package")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: i32,
    #[sea_orm(primary_key)]
    pub qualified_package_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::Id"
    )]
    Sbom,
    #[sea_orm(
        belongs_to = "super::qualified_package::Entity",
        from = "Column::QualifiedPackageId",
        to = "super::qualified_package::Column::Id"
    )]
    Package,
}

impl ActiveModelBehavior for ActiveModel {}
