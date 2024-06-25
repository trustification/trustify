use crate::advisory::model::AdvisoryHead;
use crate::package::model::{PackageHead, PackageVersionHead, QualifiedPackageHead};
use crate::vulnerability::model::VulnerabilityHead;
use crate::Error;
use sea_orm::{
    ColumnTrait, EntityTrait, LoaderTrait, ModelTrait, QueryFilter, QuerySelect, RelationTrait,
};
use sea_query::{Asterisk, Expr, Func, JoinType, SimpleExpr};
use serde::{Deserialize, Serialize};
use trustify_common::db::{ConnectionOrTransaction, VersionMatches};
use trustify_entity::{
    advisory, organization, package, package_status, package_version, qualified_package, status,
    version_range, vulnerability,
};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PackageVersionDetails {
    #[serde(flatten)]
    pub head: PackageVersionHead,
    pub base: PackageHead,
    pub packages: Vec<QualifiedPackageHead>,
    pub advisories: Vec<PackageVersionAdvisory>,
}

impl PackageVersionDetails {
    pub async fn from_entity(
        package: Option<package::Model>,
        package_version: &package_version::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let package = if let Some(package) = package {
            package
        } else {
            package_version
                .find_related(package::Entity)
                .one(tx)
                .await?
                .ok_or(Error::Data("underlying package missing".to_string()))?
        };

        let qualified_packages = package_version
            .find_related(qualified_package::Entity)
            .all(tx)
            .await?;

        let qualified_packages =
            QualifiedPackageHead::from_entities(&package, package_version, &qualified_packages, tx)
                .await?;

        let statuses = package_status::Entity::find()
            .columns([
                version_range::Column::Id,
                version_range::Column::LowVersion,
                version_range::Column::LowInclusive,
                version_range::Column::HighVersion,
                version_range::Column::HighInclusive,
            ])
            .left_join(package::Entity)
            .join(JoinType::LeftJoin, package::Relation::PackageVersions.def())
            .left_join(version_range::Entity)
            .filter(package_status::Column::PackageId.eq(package.id))
            .filter(SimpleExpr::FunctionCall(
                Func::cust(VersionMatches)
                    .arg(Expr::col(package_version::Column::Version))
                    .arg(Expr::col((version_range::Entity, Asterisk))),
            ))
            .all(tx)
            .await?;

        Ok(Self {
            head: PackageVersionHead::from_entity(&package, package_version, tx).await?,
            base: PackageHead::from_entity(&package, tx).await?,
            packages: qualified_packages,
            advisories: PackageVersionAdvisory::from_entities(statuses, tx).await?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PackageVersionAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<PackageVersionStatus>,
}

impl PackageVersionAdvisory {
    pub async fn from_entities(
        statuses: Vec<package_status::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let vulns = statuses.load_one(vulnerability::Entity, tx).await?;

        let advisories = statuses.load_one(advisory::Entity, tx).await?;

        let mut results: Vec<Self> = Vec::new();

        for ((vuln, advisory), status) in vulns.iter().zip(advisories.iter()).zip(statuses.iter()) {
            if let (Some(vulnerability), Some(advisory)) = (vuln, advisory) {
                let qualified_package_status =
                    PackageVersionStatus::from_entity(vulnerability, status, tx).await?;

                if let Some(entry) = results.iter_mut().find(|e| e.head.uuid == advisory.id) {
                    entry.status.push(qualified_package_status)
                } else {
                    let organization = advisory.find_related(organization::Entity).one(tx).await?;

                    results.push(Self {
                        head: AdvisoryHead::from_entity(advisory, organization, tx).await?,
                        status: vec![qualified_package_status],
                    })
                }
            }
        }

        Ok(results)
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PackageVersionStatus {
    pub vulnerability: VulnerabilityHead,
    pub status: String,
}

impl PackageVersionStatus {
    pub async fn from_entity(
        vuln: &vulnerability::Model,
        package_status: &package_status::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let status = package_status.find_related(status::Entity).one(tx).await?;

        let status = status.map(|e| e.slug).unwrap_or("unknown".to_string());

        Ok(Self {
            vulnerability: VulnerabilityHead::from_vulnerability_entity(vuln, tx).await?,
            status,
        })
    }
}
