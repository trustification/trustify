use crate::package::model::{PackageHead, PackageVersionHead, QualifiedPackageHead};
use crate::Error;
use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{package, package_version, qualified_package};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PackageVersionDetails {
    #[serde(flatten)]
    pub head: PackageVersionHead,
    pub base: PackageHead,
    pub packages: Vec<QualifiedPackageHead>,
}

impl PackageVersionDetails {
    pub async fn from_entity(
        package_version: &package_version::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let package = package_version
            .find_related(package::Entity)
            .one(tx)
            .await?
            .ok_or(Error::Data(
                "underlying package missing for package-version".to_string(),
            ))?;

        let qualified_packages = package_version
            .find_related(qualified_package::Entity)
            .all(tx)
            .await?;

        let qualified_packages =
            QualifiedPackageHead::from_entities(&package, package_version, &qualified_packages, tx)
                .await?;

        Ok(Self {
            head: PackageVersionHead::from_entity(&package, package_version, tx).await?,
            base: PackageHead::from_entity(&package, tx).await?,
            packages: qualified_packages,
        })
    }
}
