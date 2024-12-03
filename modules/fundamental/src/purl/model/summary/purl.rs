use crate::purl::model::{BasePurlHead, PurlHead, VersionedPurlHead};
use crate::Error;
use sea_orm::{ConnectionTrait, LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trustify_entity::{base_purl, qualified_purl, versioned_purl};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, ToSchema)]
pub struct PurlSummary {
    #[serde(flatten)]
    pub head: PurlHead,
    pub base: BasePurlHead,
    pub version: VersionedPurlHead,
    pub qualifiers: BTreeMap<String, String>,
}

impl PurlSummary {
    pub async fn from_entities<C: ConnectionTrait>(
        qualified_packages: &Vec<qualified_purl::Model>,
        tx: &C,
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
                        base: BasePurlHead::from_entity(&package).await?,
                        version: VersionedPurlHead::from_entity(&package, package_version, tx)
                            .await?,
                        qualifiers: qualified_package.qualifiers.0.clone(),
                    })
                }
            }
        }

        Ok(summaries)
    }

    pub async fn from_entity<C: ConnectionTrait>(
        base_purl: &base_purl::Model,
        versioned_purl: &versioned_purl::Model,
        purl: &qualified_purl::Model,
        db: &C,
    ) -> Result<Self, Error> {
        Ok(PurlSummary {
            head: PurlHead::from_entity(base_purl, versioned_purl, purl, db).await?,
            base: BasePurlHead::from_entity(base_purl).await?,
            version: VersionedPurlHead::from_entity(base_purl, versioned_purl, db).await?,
            qualifiers: purl.qualifiers.0.clone(),
        })
    }
}
