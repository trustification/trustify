use crate::Error;
use crate::purl::model::{BasePurlHead, PurlHead, VersionedPurlHead};
use sea_orm::{ConnectionTrait, LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trustify_common::purl::Purl;
use trustify_entity::qualified_purl::{CanonicalPurl, Qualifiers};
use trustify_entity::{base_purl, qualified_purl, versioned_purl};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, ToSchema, Hash)]
pub struct PurlSummary {
    #[serde(flatten)]
    pub head: PurlHead,
    #[deprecated]
    pub base: BasePurlHead,
    #[deprecated]
    pub version: VersionedPurlHead,
    #[deprecated]
    pub qualifiers: BTreeMap<String, String>,
}

impl From<CanonicalPurl> for PurlSummary {
    fn from(value: CanonicalPurl) -> Self {
        let purl = Purl::from(value.clone());

        let base_purl_id = purl.package_uuid();
        let versioned_purl_id = purl.version_uuid();
        let qualified_purl_id = purl.qualifier_uuid();

        PurlSummary::from_entity(
            &base_purl::Model {
                id: base_purl_id,
                r#type: purl.ty.clone(),
                namespace: purl.namespace.clone(),
                name: purl.name.clone(),
            },
            &versioned_purl::Model {
                id: purl.version_uuid(),
                base_purl_id,
                version: purl.version.clone().unwrap_or_default(),
            },
            &qualified_purl::Model {
                id: qualified_purl_id,
                versioned_purl_id,
                qualifiers: Qualifiers(purl.qualifiers),
                purl: value,
            },
        )
    }
}

impl PurlSummary {
    #[allow(deprecated)]
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
                        head: PurlHead::from_entity(&package, package_version, qualified_package),
                        base: BasePurlHead::from_entity(&package),
                        version: VersionedPurlHead::from_entity(&package, package_version),
                        qualifiers: qualified_package.qualifiers.0.clone(),
                    })
                }
            }
        }

        Ok(summaries)
    }

    #[allow(deprecated)]
    pub fn from_entity(
        base_purl: &base_purl::Model,
        versioned_purl: &versioned_purl::Model,
        purl: &qualified_purl::Model,
    ) -> Self {
        PurlSummary {
            head: PurlHead::from_entity(base_purl, versioned_purl, purl),
            base: BasePurlHead::from_entity(base_purl),
            version: VersionedPurlHead::from_entity(base_purl, versioned_purl),
            qualifiers: purl.qualifiers.0.clone(),
        }
    }
}
