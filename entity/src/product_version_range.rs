use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "product_version_range")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub product_id: Uuid,
    pub version_range_id: Uuid,
    pub cpe_key: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::product::Entity",
        from = "Column::ProductId"
        to = "super::product::Column::Id")]
    Product,
    #[sea_orm(belongs_to = "super::version_range::Entity"
        from = "Column::VersionRangeId",
        to = "super::version_range::Column::Id"
    )]
    VersionRange,
}

impl Related<super::product::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Product.def()
    }
}

impl Related<super::version_range::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VersionRange.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
