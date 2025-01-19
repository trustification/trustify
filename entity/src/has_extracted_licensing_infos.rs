use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "has_extracted_licensing_infos")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub sbom_id: Uuid,
    pub licenseId: String,
    // pub name: String,
    pub extractedText: String,
    pub comment: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::license::Entity")]
    License,
}

impl Related<super::license::Entity> for Entity {
    fn to() -> RelationDef {
        crate::license::Relation::LicenseRefInfo.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
