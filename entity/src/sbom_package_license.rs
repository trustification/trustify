use async_graphql::Enum;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sbom_package_license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sbom_id: Uuid,
    #[sea_orm(primary_key)]
    pub node_id: String,
    #[sea_orm(primary_key)]
    pub license_id: Uuid,
    #[sea_orm(primary_key)]
    pub license_type: LicenseCategory,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom::Entity",
        from = "Column::SbomId",
        to = "super::sbom::Column::SbomId"
    )]
    Sbom,
    #[sea_orm(has_many = "super::sbom_package::Entity")]
    Package,
    #[sea_orm(has_one = "super::license::Entity")]
    License,
}

#[derive(Copy, Clone, Debug, strum::Display, Eq, PartialEq, EnumIter, Enum, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum LicenseCategory {
    Declared = 0,
    Concluded = 1,
}

impl LicenseCategory {
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for LicenseCategory {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LicenseCategory::Declared),
            1 => Ok(LicenseCategory::Concluded),
            _ => Err("Invalid value for LicenseCategory"),
        }
    }
}

impl Related<super::sbom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sbom.def()
    }
}

impl Related<super::sbom_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl Related<super::license::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::License.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
