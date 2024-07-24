use crate::{
    advisory::model::AdvisoryHead,
    purl::model::{BasePurlHead, PurlHead, VersionedPurlHead},
    vulnerability::model::VulnerabilityHead,
    Error,
};
use sea_orm::{
    ColumnTrait, EntityTrait, LoaderTrait, ModelTrait, QueryFilter, QuerySelect, RelationTrait,
};
use sea_query::{Asterisk, ColumnRef, Expr, Func, IntoIden, JoinType, SimpleExpr};
use serde::{Deserialize, Serialize};
use trustify_common::db::{ConnectionOrTransaction, VersionMatches};
use trustify_common::purl::Purl;
use trustify_entity::{
    advisory, base_purl, cpe, organization, purl_status, qualified_purl, status, version_range,
    versioned_purl, vulnerability,
};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PurlDetails {
    #[serde(flatten)]
    pub head: PurlHead,
    pub version: VersionedPurlHead,
    pub base: BasePurlHead,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<PurlAdvisory>,
}

impl PurlDetails {
    pub async fn from_entity(
        package: Option<base_purl::Model>,
        package_version: Option<versioned_purl::Model>,
        qualified_package: &qualified_purl::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let package_version = if let Some(package_version) = package_version {
            package_version
        } else {
            qualified_package
                .find_related(versioned_purl::Entity)
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
                .find_related(base_purl::Entity)
                .one(tx)
                .await?
                .ok_or(Error::Data("underlying package missing".to_string()))?
        };

        let statuses = purl_status::Entity::find()
            .columns([
                version_range::Column::Id,
                version_range::Column::LowVersion,
                version_range::Column::LowInclusive,
                version_range::Column::HighVersion,
                version_range::Column::HighInclusive,
            ])
            .left_join(base_purl::Entity)
            .join(
                JoinType::LeftJoin,
                base_purl::Relation::VersionedPurls.def(),
            )
            .left_join(version_range::Entity)
            .filter(purl_status::Column::BasePurlId.eq(package.id))
            .filter(SimpleExpr::FunctionCall(
                Func::cust(VersionMatches)
                    .arg(Expr::col(versioned_purl::Column::Version))
                    .arg(Expr::col((version_range::Entity, Asterisk))),
            ))
            .distinct_on([ColumnRef::TableColumn(
                purl_status::Entity.into_iden(),
                purl_status::Column::Id.into_iden(),
            )])
            .all(tx)
            .await?;

        Ok(PurlDetails {
            head: PurlHead::from_entity(&package, &package_version, qualified_package, tx).await?,
            version: VersionedPurlHead::from_entity(&package, &package_version, tx).await?,
            base: BasePurlHead::from_entity(&package, tx).await?,
            advisories: PurlAdvisory::from_entities(statuses, tx).await?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PurlAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<PurlStatus>,
}

impl PurlAdvisory {
    pub async fn from_entities(
        statuses: Vec<purl_status::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let vulns = statuses.load_one(vulnerability::Entity, tx).await?;

        let advisories = statuses.load_one(advisory::Entity, tx).await?;

        let mut results: Vec<PurlAdvisory> = Vec::new();

        for ((vuln, advisory), status) in vulns
            .into_iter()
            .zip(advisories.iter())
            .zip(statuses.iter())
        {
            let vulnerability = vuln.unwrap_or(vulnerability::Model {
                id: status.vulnerability_id.clone(),
                title: None,
                published: None,
                modified: None,
                withdrawn: None,
                cwe: None,
            });

            if let Some(advisory) = advisory {
                let qualified_package_status =
                    PurlStatus::from_entity(&vulnerability, status, tx).await?;

                if let Some(entry) = results.iter_mut().find(|e| e.head.uuid == advisory.id) {
                    entry.status.push(qualified_package_status)
                } else {
                    let organization = advisory.find_related(organization::Entity).one(tx).await?;

                    results.push(Self {
                        head: AdvisoryHead::from_advisory(advisory, Some(organization), tx).await?,
                        status: vec![qualified_package_status],
                    })
                }
            }
        }

        Ok(results)
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PurlStatus {
    pub vulnerability: VulnerabilityHead,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<StatusContext>,
}

#[derive(Serialize, Clone, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum StatusContext {
    Purl(Purl),
    Cpe(String),
}

impl PurlStatus {
    pub async fn from_entity(
        vuln: &vulnerability::Model,
        package_status: &purl_status::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let status = status::Entity::find_by_id(package_status.status_id)
            .one(tx)
            .await?;

        let status = status.map(|e| e.slug).unwrap_or("unknown".to_string());

        let cpe = if let Some(context_cpe) = package_status.context_cpe_id {
            let cpe = cpe::Entity::find_by_id(context_cpe).one(tx).await?;

            cpe.map(|cpe| cpe.to_string())
        } else {
            None
        };

        Ok(Self {
            vulnerability: VulnerabilityHead::from_vulnerability_entity(vuln, tx).await?,
            status,
            context: cpe.map(StatusContext::Cpe),
        })
    }
}
