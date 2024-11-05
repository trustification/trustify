use crate::sbom::model::SbomHead;
use crate::{
    advisory::model::AdvisoryHead,
    purl::model::{BasePurlHead, PurlHead, VersionedPurlHead},
    vulnerability::model::VulnerabilityHead,
    Error,
};
use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, FromQueryResult, LoaderTrait, ModelTrait, QueryFilter,
    QueryResult, QuerySelect, RelationTrait, Select,
};
use sea_query::{Asterisk, ColumnRef, Expr, Func, IntoIden, JoinType, SimpleExpr};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use trustify_common::db::multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel};
use trustify_common::db::{ConnectionOrTransaction, VersionMatches};
use trustify_common::memo::Memo;
use trustify_common::purl::Purl;
use trustify_entity::{
    advisory, base_purl, cpe, license, organization, purl_license_assertion, purl_status,
    qualified_purl, sbom, status, version_range, versioned_purl, vulnerability,
};
use trustify_module_ingestor::common::{Deprecation, DeprecationForExt};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PurlDetails {
    #[serde(flatten)]
    pub head: PurlHead,
    pub version: VersionedPurlHead,
    pub base: BasePurlHead,
    pub advisories: Vec<PurlAdvisory>,
    pub licenses: Vec<PurlLicenseSummary>,
}

impl PurlDetails {
    pub async fn from_entity(
        package: Option<base_purl::Model>,
        package_version: Option<versioned_purl::Model>,
        qualified_package: &qualified_purl::Model,
        deprecation: Deprecation,
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
            .filter(purl_status::Column::BasePurlId.eq(package.id))
            .left_join(version_range::Entity)
            .columns(version_range::Column::iter())
            .left_join(base_purl::Entity)
            .filter(SimpleExpr::FunctionCall(
                Func::cust(VersionMatches)
                    .arg(Expr::value(package_version.version.clone()))
                    .arg(Expr::col((version_range::Entity, Asterisk))),
            ))
            .distinct_on([ColumnRef::TableColumn(
                purl_status::Entity.into_iden(),
                purl_status::Column::Id.into_iden(),
            )])
            .with_deprecation_related(deprecation)
            .all(tx)
            .await?;

        let licenses = purl_license_assertion::Entity::find()
            .join(
                JoinType::LeftJoin,
                purl_license_assertion::Relation::VersionedPurl.def(),
            )
            .join(
                JoinType::LeftJoin,
                purl_license_assertion::Relation::License.def(),
            )
            .join(
                JoinType::LeftJoin,
                purl_license_assertion::Relation::Sbom.def(),
            )
            .filter(versioned_purl::Column::Id.eq(package_version.id))
            .try_into_multi_model::<LicenseCatcher>()?
            .all(tx)
            .await?;

        Ok(PurlDetails {
            head: PurlHead::from_entity(&package, &package_version, qualified_package, tx).await?,
            version: VersionedPurlHead::from_entity(&package, &package_version, tx).await?,
            base: BasePurlHead::from_entity(&package, tx).await?,
            advisories: PurlAdvisory::from_entities(statuses, tx).await?,
            licenses: PurlLicenseSummary::from_entities(&licenses, tx).await?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema, PartialEq, Eq)]
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
                reserved: None,
                published: None,
                modified: None,
                withdrawn: None,
                cwes: None,
            });

            if let Some(advisory) = advisory {
                let qualified_package_status =
                    PurlStatus::from_entity(&vulnerability, status, tx).await?;

                if let Some(entry) = results.iter_mut().find(|e| e.head.uuid == advisory.id) {
                    entry.status.push(qualified_package_status)
                } else {
                    let organization = advisory.find_related(organization::Entity).one(tx).await?;

                    results.push(Self {
                        head: AdvisoryHead::from_advisory(
                            advisory,
                            Memo::Provided(organization),
                            tx,
                        )
                        .await?,
                        status: vec![qualified_package_status],
                    })
                }
            }
        }

        Ok(results)
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema, PartialEq, Eq)]
pub struct PurlStatus {
    pub vulnerability: VulnerabilityHead,
    pub status: String,
    #[schema(required)]
    pub context: Option<StatusContext>,
}

#[derive(Serialize, Clone, Deserialize, Debug, ToSchema, PartialEq, Eq)]
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
            vulnerability: VulnerabilityHead::from_vulnerability_entity(
                vuln,
                Memo::NotProvided,
                tx,
            )
            .await?,
            status,
            context: cpe.map(StatusContext::Cpe),
        })
    }
}

#[derive(Serialize, Clone, Deserialize, Debug, ToSchema)]
pub struct PurlLicenseSummary {
    pub sbom: SbomHead,
    pub licenses: Vec<String>,
}

impl PurlLicenseSummary {
    pub async fn from_entities(
        entities: &[LicenseCatcher],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = HashMap::new();

        for row in entities {
            let entry = summaries.entry(row.sbom.sbom_id);
            if let Entry::Vacant(entry) = entry {
                let summary = PurlLicenseSummary {
                    sbom: SbomHead::from_entity(&row.sbom, None, tx).await?,
                    licenses: vec![],
                };

                entry.insert(summary);
            }
        }

        for row in entities {
            if let Some(summary) = summaries.get_mut(&row.sbom.sbom_id) {
                summary.licenses.push(row.license.text.clone());
            }
        }

        Ok(summaries.values().cloned().collect())
    }
}

#[derive(Debug)]
pub struct LicenseCatcher {
    sbom: sbom::Model,
    license: license::Model,
}

impl FromQueryResult for LicenseCatcher {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            sbom: Self::from_query_result_multi_model(res, "", sbom::Entity)?,
            license: Self::from_query_result_multi_model(res, "", license::Entity)?,
        })
    }
}

impl FromQueryResultMultiModel for LicenseCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns(sbom::Entity)?
            .try_model_columns(license::Entity)
    }
}
