use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_version_range")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub package_id: Uuid,
    pub start: String,
    pub end: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::base_purl::Entity",
        from = "super::package_version_range::Column::PackageId"
        to = "super::base_purl::Column::Id")]
    Package,
}

impl Related<super::base_purl::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
