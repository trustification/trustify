use crate::Error;
use sea_orm::prelude::Uuid;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::purl::Purl;
use trustify_entity::{package, package_version, qualified_package};
use utoipa::ToSchema;

pub mod details;
pub mod summary;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PackageHead {
    /// The ID of the base PURL
    pub uuid: Uuid,
    /// The actual base PURL
    pub purl: Purl,
}

impl PackageHead {
    pub async fn from_entity(
        entity: &package::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(PackageHead {
            uuid: entity.id,
            purl: Purl {
                ty: entity.r#type.clone(),
                namespace: entity.namespace.clone(),
                name: entity.name.clone(),
                version: None,
                qualifiers: Default::default(),
            },
        })
    }

    pub async fn from_package_entities(
        entities: &Vec<package::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut heads = Vec::new();

        for entity in entities {
            heads.push(Self::from_entity(entity, tx).await?)
        }

        Ok(heads)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PackageVersionHead {
    /// The ID of the versioned PURL
    pub uuid: Uuid,
    /// The actual, versioned PURL
    pub purl: Purl,
    /// The version from the PURL
    pub version: String,
}

impl PackageVersionHead {
    pub async fn from_entity(
        package: &package::Model,
        package_version: &package_version::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            uuid: package_version.id,
            purl: Purl {
                ty: package.r#type.clone(),
                namespace: package.namespace.clone(),
                name: package.name.clone(),
                version: Some(package_version.version.clone()),
                qualifiers: Default::default(),
            },
            version: package_version.version.clone(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct QualifiedPackageHead {
    /// The ID of the qualified PURL
    pub uuid: Uuid,
    /// The actual qualified PURL
    pub purl: Purl,
}

impl QualifiedPackageHead {
    pub async fn from_entity(
        package: &package::Model,
        package_version: &package_version::Model,
        qualified_package: &qualified_package::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            uuid: qualified_package.id,
            purl: Purl {
                ty: package.r#type.clone(),
                namespace: package.namespace.clone(),
                name: package.name.clone(),
                version: Some(package_version.version.clone()),
                qualifiers: qualified_package.qualifiers.0.clone(),
            },
        })
    }

    pub async fn from_entities(
        package: &package::Model,
        package_version: &package_version::Model,
        qualified_packages: &Vec<qualified_package::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut heads = Vec::new();

        for qualified_package in qualified_packages {
            heads.push(
                Self::from_entity(
                    &package.clone(),
                    &package_version.clone(),
                    qualified_package,
                    tx,
                )
                .await?,
            )
        }

        Ok(heads)
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TypeHead {
    pub name: String,
}
