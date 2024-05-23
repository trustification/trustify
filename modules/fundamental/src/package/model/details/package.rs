use crate::package::model::summary::package_version::PackageVersionSummary;
use crate::package::model::PackageHead;
use crate::Error;
use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{package, package_version};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PackageDetails {
    #[serde(flatten)]
    pub head: PackageHead,
    pub versions: Vec<PackageVersionSummary>,
}

impl PackageDetails {
    pub async fn from_entity(
        package: &package::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let package_versions = package
            .find_related(package_version::Entity)
            .all(tx)
            .await?;

        Ok(Self {
            head: PackageHead::from_entity(package, tx).await?,
            versions: PackageVersionSummary::from_entities_with_common_package(
                package,
                &package_versions,
                tx,
            )
            .await?,
        })
    }
}
