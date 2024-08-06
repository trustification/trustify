use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "product_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub product_id: Uuid,
    pub sbom_id: Option<Uuid>,
    pub version: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::product::Entity",
        from = "super::product_version::Column::ProductId"
        to = "super::product::Column::Id")]
    Product,
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "super::product_version::Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
}

impl Related<super::product::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Product.def()
    }
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
