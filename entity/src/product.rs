use sea_orm::entity::prelude::*;

use crate::organization;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "product")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub name: String,
    pub vendor_id: Option<Uuid>,
    pub cpe_key: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organization::Entity"
        from = "Column::VendorId"
        to = "super::organization::Column::Id")]
    Vendor,
    #[sea_orm(has_many = "super::product_version::Entity")]
    ProductVersion,
    #[sea_orm(
        has_many = "super::cpe::Entity"
        from = "Column::CpeKey"
        to = "super::cpe::Column::Product")]
    Cpe,
}

impl Related<organization::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vendor.def()
    }
}

impl Related<super::product_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProductVersion.def()
    }
}

impl Related<super::cpe::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cpe.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
