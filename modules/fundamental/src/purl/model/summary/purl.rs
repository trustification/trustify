use crate::purl::model::{BasePurlHead, PurlHead, VersionedPurlHead};
use crate::Error;
use sea_orm::{LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_entity::{base_purl, qualified_purl, versioned_purl};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct PurlSummary {
    #[serde(flatten)]
    pub head: PurlHead,
    pub base: BasePurlHead,
    pub version: VersionedPurlHead,
}

impl PurlSummary {
    pub async fn from_entities(
        qualified_packages: &Vec<qualified_purl::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let package_versions = qualified_packages
            .load_one(versioned_purl::Entity, tx)
            .await?;

        let mut summaries = Vec::new();

        for (package_version, qualified_package) in
            package_versions.iter().zip(qualified_packages.iter())
        {
            if let (Some(package_version), qualified_package) = (package_version, qualified_package)
            {
                if let Some(package) = package_version
                    .find_related(base_purl::Entity)
                    .one(tx)
                    .await?
                {
                    summaries.push(PurlSummary {
                        head: PurlHead::from_entity(
                            &package,
                            package_version,
                            qualified_package,
                            tx,
                        )
                        .await?,
                        base: BasePurlHead::from_entity(&package, tx).await?,
                        version: VersionedPurlHead::from_entity(&package, package_version, tx)
                            .await?,
                    })
                }
            }
        }

        Ok(summaries)
    }
}

paginated!(PurlSummary);
