use crate::{purl::model::VersionedPurlHead, sbom::model::SbomHead, Error};
use sea_orm::{ConnectionTrait, ModelTrait, PaginatorTrait};
use serde::{Deserialize, Serialize};
use trustify_entity::{license, purl_license_assertion};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseSummary {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,
    pub license: String,
    pub spdx_licenses: Vec<String>,
    pub spdx_license_exceptions: Vec<String>,
    pub purls: u64,
}

impl LicenseSummary {
    pub async fn from_entity(license: &license::Model, purls: u64) -> Result<Self, Error> {
        Ok(LicenseSummary {
            id: license.id,
            license: license.text.clone(),
            spdx_licenses: license.spdx_licenses.as_ref().cloned().unwrap_or_default(),
            spdx_license_exceptions: license
                .spdx_license_exceptions
                .as_ref()
                .cloned()
                .unwrap_or_default(),
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
