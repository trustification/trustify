use crate::package::model::{PackageHead, PackageVersionHead, QualifiedPackageHead};
use crate::Error;
use sea_orm::LoaderTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{package, package_version, qualified_package};

#[derive(Serialize, Deserialize, Debug)]
pub struct QualifiedPackageSummary {
    #[serde(flatten)]
    pub head: QualifiedPackageHead,
    pub base: PackageHead,
    pub version: PackageVersionHead,
}

impl QualifiedPackageSummary {
    pub async fn from_entities(
        qualified_packages: &Vec<qualified_package::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let package_versions = qualified_packages
            .load_one(package_version::Entity, tx)
            .await?;

        let packages = qualified_packages.load_one(package::Entity, tx).await?;

        let mut summaries = Vec::new();

        for ((package, package_version), qualified_package) in packages
            .iter()
            .zip(package_versions.iter())
            .zip(qualified_packages.iter())
        {
            if let (Some(package), Some(package_version), qualified_package) =
                (package, package_version, qualified_package)
            {
                summaries.push(QualifiedPackageSummary {
                    head: QualifiedPackageHead::from_entity(
                        package,
                        package_version,
                        qualified_package,
                        tx,
                    )
                    .await?,
                    base: PackageHead::from_entity(package, tx).await?,
                    version: PackageVersionHead::from_entity(package, package_version, tx).await?,
                })
            }
        }

        Ok(summaries)
    }
}
