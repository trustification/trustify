use crate::{purl::model::VersionedPurlHead, sbom::model::SbomHead, Error};
use sea_orm::{ConnectionTrait, ModelTrait, PaginatorTrait};
use serde::{Deserialize, Serialize};
use trustify_entity::license::LicenseCategory;
use trustify_entity::{license, purl_license_assertion};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseSummary {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,
    pub license: String,
    pub license_ref_id: Option<Uuid>,
    pub license_type: String,
    pub purls: u64,
}

impl LicenseSummary {
    pub async fn from_entity(license: &license::Model, purls: u64) -> Result<Self, Error> {
        fn convert_LicenseCategory(license_category: LicenseCategory) -> String {
            match license_category {
                LicenseCategory::SPDXDECLARED => return String::from("Spdx_License_Declared"),
                LicenseCategory::SPDXCONCLUDED => return String::from("Spdx_License_CONCLUDED"),
                LicenseCategory::CYDXLCID => return String::from("Cydx_LicenseChoice_Id"),
                LicenseCategory::CYDXLCNAME => return String::from("Cydx_LicenseChoice_Name"),
                LicenseCategory::CYDXLEXPRESSION => return String::from("Cydx_icenseExpression"),
                LicenseCategory::CLEARLYDEFINED => return String::from("ClearlyDefined"),
                LicenseCategory::OTHER => return String::from("Other"),
            }
        }

        Ok(LicenseSummary {
            id: license.id,
            license: license.license_id.clone(),
            license_ref_id: license.license_ref_id,
            license_type: convert_LicenseCategory(license.license_type.clone()),
            purls,
        })
    }

    pub async fn from_entities<C: ConnectionTrait>(
        licenses: &[license::Model],
        connection: &C,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        for license in licenses {
            let purls = license
                .find_related(purl_license_assertion::Entity)
                .count(connection)
                .await?;
            summaries.push(Self::from_entity(license, purls).await?)
        }

        Ok(summaries)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseDetailsPurlSummary {
    pub purl: VersionedPurlHead,
    pub sbom: SbomHead,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpdxLicenseSummary {
    pub id: String,
    pub name: String,
}

impl SpdxLicenseSummary {
    pub fn from_details(rows: &[&(&str, &str, u8)]) -> Vec<Self> {
        rows.iter()
            .map(|(id, name, _flags)| Self {
                id: id.to_string(),
                name: name.to_string(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpdxLicenseDetails {
    #[serde(flatten)]
    pub summary: SpdxLicenseSummary,
    pub text: String,
}
