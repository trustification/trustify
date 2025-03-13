use crate::Error;
use sea_orm::prelude::Uuid;
use serde::{Deserialize, Serialize};
use trustify_common::purl::Purl;
use trustify_entity::{base_purl, qualified_purl, versioned_purl};
use utoipa::ToSchema;

pub mod details;
pub mod summary;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, Hash)]
pub struct BasePurlHead {
    /// The ID of the base PURL
    pub uuid: Uuid,
    /// The actual base PURL
    pub purl: Purl,
}

impl BasePurlHead {
    pub fn from_entity(entity: &base_purl::Model) -> Self {
        BasePurlHead {
            uuid: entity.id,
            purl: Purl {
                ty: entity.r#type.clone(),
                namespace: entity.namespace.clone(),
                name: entity.name.clone(),
                version: None,
                qualifiers: Default::default(),
            },
        }
    }

    pub async fn from_package_entities(
        entities: &Vec<base_purl::Model>,
    ) -> Result<Vec<Self>, Error> {
        let mut heads = Vec::new();

        for entity in entities {
            heads.push(Self::from_entity(entity))
        }

        Ok(heads)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, Hash)]
pub struct VersionedPurlHead {
    /// The ID of the versioned PURL
    pub uuid: Uuid,
    /// The actual, versioned PURL
    pub purl: Purl,
    /// The version from the PURL
    pub version: String,
}

impl VersionedPurlHead {
    pub fn from_entity(
        package: &base_purl::Model,
        package_version: &versioned_purl::Model,
    ) -> Self {
        Self {
            uuid: package_version.id,
            purl: Purl {
                ty: package.r#type.clone(),
                namespace: package.namespace.clone(),
                name: package.name.clone(),
                version: Some(package_version.version.clone()),
                qualifiers: Default::default(),
            },
            version: package_version.version.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, Hash)]
pub struct PurlHead {
    /// The ID of the qualified PURL
    pub uuid: Uuid,
    /// The actual qualified PURL
    pub purl: Purl,
}

impl PurlHead {
    pub fn from_entity(
        package: &base_purl::Model,
        package_version: &versioned_purl::Model,
        qualified_package: &qualified_purl::Model,
    ) -> Self {
        Self {
            uuid: qualified_package.id,
            purl: Purl {
                ty: package.r#type.clone(),
                namespace: package.namespace.clone(),
                name: package.name.clone(),
                version: Some(package_version.version.clone()),
                qualifiers: qualified_package.qualifiers.0.clone(),
            },
        }
    }

    pub fn from_entities(
        package: &base_purl::Model,
        package_version: &versioned_purl::Model,
        qualified_packages: &Vec<qualified_purl::Model>,
    ) -> Vec<Self> {
        let mut heads = Vec::new();

        for qualified_package in qualified_packages {
            heads.push(Self::from_entity(
                &package.clone(),
                &package_version.clone(),
                qualified_package,
            ))
        }

        heads
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TypeHead {
    pub name: String,
}
