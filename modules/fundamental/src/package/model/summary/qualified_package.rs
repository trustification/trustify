use crate::package::model::{PackageHead, PackageVersionHead, QualifiedPackageHead};
use crate::Error;
use sea_orm::{LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_entity::{package, package_version, qualified_package};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
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

        let mut summaries = Vec::new();

        for (package_version, qualified_package) in
            package_versions.iter().zip(qualified_packages.iter())
        {
            if let (Some(package_version), qualified_package) = (package_version, qualified_package)
            {
                if let Some(package) = package_version
                    .find_related(package::Entity)
                    .one(tx)
                    .await?
                {
                    summaries.push(QualifiedPackageSummary {
                        head: QualifiedPackageHead::from_entity(
                            &package,
                            package_version,
                            qualified_package,
                            tx,
                        )
                        .await?,
                        base: PackageHead::from_entity(&package, tx).await?,
                        version: PackageVersionHead::from_entity(&package, package_version, tx)
                            .await?,
                    })
                }
            }
        }

        Ok(summaries)
    }
}

paginated!(QualifiedPackageSummary);
