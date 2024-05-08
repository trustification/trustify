use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cpe")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub part: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub update: Option<String>,
    pub edition: Option<String>,
    pub language: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_package_cpe_ref::Entity",
        from = "Column::Id",
        to = "super::sbom_package_cpe_ref::Column::CpeId"
    )]
    SbomPackage,
}

impl Related<super::sbom_package_cpe_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SbomPackage.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
