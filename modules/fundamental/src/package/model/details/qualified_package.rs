use crate::package::model::{PackageHead, PackageVersionHead, QualifiedPackageHead};
use crate::Error;
use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{package, package_version, qualified_package};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct QualifiedPackageDetails {
    #[serde(flatten)]
    pub head: QualifiedPackageHead,
    pub version: PackageVersionHead,
    pub base: PackageHead,
    // TODO link to advisories, sboms, etc
}

impl QualifiedPackageDetails {
    pub async fn from_entity(
        package: Option<package::Model>,
        package_version: Option<package_version::Model>,
        qualified_package: &qualified_package::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let package_version = if let Some(package_version) = package_version {
            package_version
        } else {
            qualified_package
                .find_related(package_version::Entity)
                .one(tx)
                .await?
                .ok_or(Error::Data(
                    "underlying package-version missing".to_string(),
                ))?
        };

        let package = if let Some(package) = package {
            package
        } else {
            package_version
                .find_related(package::Entity)
                .one(tx)
                .await?
                .ok_or(Error::Data("underlying package missing".to_string()))?
        };

        Ok(QualifiedPackageDetails {
            head: QualifiedPackageHead::from_entity(
                &package,
                &package_version,
                qualified_package,
                tx,
            )
            .await?,
            version: PackageVersionHead::from_entity(&package, &package_version, tx).await?,
            base: PackageHead::from_entity(&package, tx).await?,
        })
    }
}
