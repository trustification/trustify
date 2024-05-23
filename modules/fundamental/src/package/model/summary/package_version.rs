use crate::package::model::{PackageHead, PackageVersionHead, QualifiedPackageHead};
use crate::Error;
use sea_orm::LoaderTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{package, package_version, qualified_package};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PackageVersionSummary {
    #[serde(flatten)]
    pub head: PackageVersionHead,
    pub base: PackageHead,
    pub packages: Vec<QualifiedPackageHead>,
}

impl PackageVersionSummary {
    pub async fn from_entities_with_common_package(
        package: &package::Model,
        package_versions: &Vec<package_version::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        let qualified_packages = package_versions
            .load_many(qualified_package::Entity, tx)
            .await?;

        for (package_version, qualified_packages) in
            package_versions.iter().zip(qualified_packages.iter())
        {
            summaries.push(Self {
                head: PackageVersionHead::from_entity(package, package_version, tx).await?,
                base: PackageHead::from_entity(package, tx).await?,
                packages: QualifiedPackageHead::from_entities(
                    package,
                    package_version,
                    qualified_packages,
                    tx,
                )
                .await?,
            })
        }

        Ok(summaries)
    }
}
