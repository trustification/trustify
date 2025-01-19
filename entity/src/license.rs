use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "license")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub license_id: String,
    // pub license_name: String,
    // pub spdx_licenses: Option<Vec<String>>,
    // pub spdx_license_exceptions: Option<Vec<String>>,
    #[sea_orm(nullable)]
    pub license_ref_id: Option<Uuid>,
    pub license_type: LicenseCategory,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::purl_license_assertion::Entity")]
    PurlAssertions,

    #[sea_orm(belongs_to="super::has_extracted_licensing_infos::Entity"
    from = "Column::LicenseRefId",
    to = "super::has_extracted_licensing_infos::Column::Id",
    )]
    LicenseRefInfo,
}

impl Related<super::purl_license_assertion::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PurlAssertions.def()
    }
}

impl Related<super::has_extracted_licensing_infos::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::LicenseRefInfo.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum")]
pub enum LicenseCategory {
    #[sea_orm(string_value = "Spdx_License_Declared")]
    SPDXDECLARED,
    #[sea_orm(string_value = "Spdx_License_CONCLUDED")]
    SPDXCONCLUDED,
    #[sea_orm(string_value = "Cydx_LicenseChoice_Id")]
    CYDXLCID,
    #[sea_orm(string_value = "Cydx_LicenseChoice_Name")]
    CYDXLCNAME,
    #[sea_orm(string_value = "Cydx_icenseExpression")]
    CYDXLEXPRESSION,
    #[sea_orm(string_value = "ClearlyDefined")]
    CLEARLYDEFINED,
    #[sea_orm(string_value = "Other")]
    OTHER,
}

impl fmt::Display for LicenseCategory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str_value = match self {
            LicenseCategory::SPDXDECLARED => "Spdx_License_Declared",
            LicenseCategory::SPDXCONCLUDED => "Spdx_License_CONCLUDED",
            LicenseCategory::CYDXLCID => "Cydx_LicenseChoice_Id",
            LicenseCategory::CYDXLCNAME => "Cydx_LicenseChoice_Name",
            LicenseCategory::CYDXLEXPRESSION => "Cydx_LicenseExpression",
            LicenseCategory::CLEARLYDEFINED => "ClearlyDefined",
            LicenseCategory::OTHER => "Other",
        };
        write!(f, "{}", str_value)
    }
}

impl Default for LicenseCategory {
    fn default() -> Self {
        LicenseCategory::OTHER
    }
}
