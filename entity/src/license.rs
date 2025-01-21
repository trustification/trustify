use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
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

    #[sea_orm(belongs_to="super::extracted_licensing_infos::Entity"
    from = "Column::LicenseRefId",
    to = "super::extracted_licensing_infos::Column::Id",
    )]
    LicenseRefInfo,
}

impl Related<super::purl_license_assertion::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PurlAssertions.def()
    }
}

impl Related<super::extracted_licensing_infos::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::LicenseRefInfo.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

// #[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "license_category")]
pub enum LicenseCategory {
    #[sea_orm(string_value = "slc")]
    SPDXDECLARED,
    #[sea_orm(string_value = "sld")]
    SPDXCONCLUDED,
    #[sea_orm(string_value = "clci")]
    CYDXLCID,
    #[sea_orm(string_value = "clcn")]
    CYDXLCNAME,
    #[sea_orm(string_value = "cle")]
    CYDXLEXPRESSION,
    #[sea_orm(string_value = "cd")]
    CLEARLYDEFINED,
    #[sea_orm(string_value = "o")]
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

impl From<&str> for LicenseCategory {
    fn from(value: &str) -> Self {
        match value {
            "A" => LicenseCategory::SPDXDECLARED,
            "B" => LicenseCategory::SPDXCONCLUDED,
            "C" => LicenseCategory::CYDXLCID,
            "D" => LicenseCategory::CYDXLCNAME,
            "E" => LicenseCategory::CYDXLEXPRESSION,
            "F" => LicenseCategory::CLEARLYDEFINED,
            "O" => LicenseCategory::OTHER,
            // _ => Err("Invalid LicenseCategory value"),
            _ => LicenseCategory::OTHER,
        }
    }
}

impl Default for LicenseCategory {
    fn default() -> Self {
        LicenseCategory::OTHER
    }
}
