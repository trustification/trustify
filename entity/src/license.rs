use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub text: String,
    pub spdx_licenses: Option<Vec<String>>,
    pub spdx_license_exceptions: Option<Vec<String>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_package_license::Entity",
        from = "(Column::Id)",
        to = "(super::sbom_package_license::Column::LicenseId)"
    )]
    PackageLicense,
}

impl Related<super::sbom_package_license::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PackageLicense.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
