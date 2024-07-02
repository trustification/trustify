use crate::purl::model::summary::versioned_purl::VersionedPurlSummary;
use crate::purl::model::BasePurlHead;
use crate::Error;
use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{base_purl, versioned_purl};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct BasePurlDetails {
    #[serde(flatten)]
    pub head: BasePurlHead,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<VersionedPurlSummary>,
}

impl BasePurlDetails {
    pub async fn from_entity(
        package: &base_purl::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let package_versions = package.find_related(versioned_purl::Entity).all(tx).await?;

        Ok(Self {
            head: BasePurlHead::from_entity(package, tx).await?,
            versions: VersionedPurlSummary::from_entities_with_common_package(
                package,
                &package_versions,
                tx,
            )
            .await?,
        })
    }
}
