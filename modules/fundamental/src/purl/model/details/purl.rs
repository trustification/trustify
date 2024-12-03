use crate::{
    advisory::model::AdvisoryHead,
    purl::model::{BasePurlHead, PurlHead, VersionedPurlHead},
    sbom::model::SbomHead,
    vulnerability::model::VulnerabilityHead,
    Error,
};
use ::cpe::uri::OwnedUri;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, LoaderTrait, ModelTrait,
    QueryFilter, QueryOrder, QueryResult, QuerySelect, QueryTrait, RelationTrait, Select,
};
use sea_query::{Asterisk, ColumnRef, Expr, Func, IntoIden, JoinType, SimpleExpr};
use serde::{Deserialize, Serialize};
use std::{collections::hash_map::Entry, collections::HashMap};
use strum::IntoEnumIterator;
use trustify_common::{
    db::multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
    db::VersionMatches,
    memo::Memo,
    purl::Purl,
};
use trustify_entity::{
    advisory, base_purl, cpe, license, organization, product, product_status, product_version,
    product_version_range, purl_license_assertion, purl_status, qualified_purl, sbom, sbom_package,
    sbom_package_purl_ref, status, version_range, versioned_purl, vulnerability,
};
use trustify_module_ingestor::common::{Deprecation, DeprecationForExt};
use utoipa::ToSchema;
use uuid::Uuid;

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
    pub async fn from_entity<C: ConnectionTrait>(
        package: Option<base_purl::Model>,
        package_version: Option<versioned_purl::Model>,
        qualified_package: &qualified_purl::Model,
        deprecation: Deprecation,
        tx: &C,
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

        let purl_statuses = purl_status::Entity::find()
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

        let product_statuses = get_product_statuses_for_purl(
            tx,
            qualified_package.id,
            &package.name,
            package.namespace.as_deref(),
        )
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
            base: BasePurlHead::from_entity(&package).await?,
            advisories: PurlAdvisory::from_entities(purl_statuses, product_statuses, tx).await?,
            licenses: PurlLicenseSummary::from_entities(&licenses, tx).await?,
        })
    }
}

async fn get_product_statuses_for_purl<C: ConnectionTrait>(
    tx: &C,
    qualified_package_id: Uuid,
    purl_name: &str,
    namespace_name: Option<&str>,
) -> Result<Vec<ProductStatusCatcher>, Error> {
    // Subquery to get all SBOM IDs for the given purl
    let sbom_ids_query = sbom::Entity::find()
        .join(JoinType::Join, sbom::Relation::Packages.def())
        .join(JoinType::Join, sbom_package::Relation::Purl.def())
        .filter(sbom_package_purl_ref::Column::QualifiedPurlId.eq(qualified_package_id))
        .select_only()
        .column(sbom::Column::SbomId)
        .into_query();

    // Main query to get product statuses
    let product_statuses_query = product_status::Entity::find()
        .join(JoinType::Join, product_status::Relation::ContextCpe.def())
        .join(
            JoinType::Join,
            product_status::Relation::ProductVersionRange.def(),
        )
        .join(
            JoinType::Join,
            product_version_range::Relation::VersionRange.def(),
        )
        .join(JoinType::Join, cpe::Relation::Product.def())
        .join(JoinType::LeftJoin, product::Relation::ProductVersion.def())
        .join(JoinType::Join, product_status::Relation::Status.def())
        .join(JoinType::Join, product_status::Relation::Advisory.def())
        .filter(product_version::Column::SbomId.in_subquery(sbom_ids_query))
        .filter(Expr::col(product_status::Column::Package).eq(purl_name).or(
            namespace_name.map_or(Expr::value(false), |ns| {
                Expr::col(product_status::Column::Package).eq(format!("{}/{}", ns, purl_name))
            }),
        ))
        .distinct_on([
            (product_status::Entity, product_status::Column::ContextCpeId),
            (product_status::Entity, product_status::Column::StatusId),
            (product_status::Entity, product_status::Column::Package),
            (
                product_status::Entity,
                product_status::Column::VulnerabilityId,
            ),
        ])
        .order_by_asc(product_status::Column::ContextCpeId)
        .order_by_asc(product_status::Column::StatusId)
        .order_by_asc(product_status::Column::Package)
        .order_by_asc(product_status::Column::VulnerabilityId);

    let product_statuses = product_statuses_query
        .try_into_multi_model::<ProductStatusCatcher>()?
        .all(tx)
        .await?;

    Ok(product_statuses)
}

#[derive(Serialize, Deserialize, Debug, ToSchema, PartialEq, Eq)]
pub struct PurlAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<PurlStatus>,
}

impl PurlAdvisory {
    pub async fn from_entities<C: ConnectionTrait>(
        purl_statuses: Vec<purl_status::Model>,
        product_statuses: Vec<ProductStatusCatcher>,
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        let vulns = purl_statuses.load_one(vulnerability::Entity, tx).await?;

        let advisories = purl_statuses.load_one(advisory::Entity, tx).await?;

        let mut results: Vec<PurlAdvisory> = Vec::new();

        for ((vuln, advisory), status) in vulns
            .into_iter()
            .zip(advisories.iter())
            .zip(purl_statuses.iter())
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

        for product_status in product_statuses {
            let vuln = vulnerability::Model {
                id: product_status.product_status.vulnerability_id.clone(),
                title: None,
                reserved: None,
                published: None,
                modified: None,
                withdrawn: None,
                cwes: None,
            };

            let advisory_cpe: Option<OwnedUri> = (&product_status.cpe).try_into().ok();

            let purl_status = PurlStatus {
                vulnerability: VulnerabilityHead::from_vulnerability_entity(
                    &vuln,
                    Memo::NotProvided,
                    tx,
                )
                .await?,
                status: product_status.status.slug,
                context: advisory_cpe
                    .as_ref()
                    .map(|e| StatusContext::Cpe(e.to_string())),
            };

            if let Some(entry) = results
                .iter_mut()
                .find(|e| e.head.uuid == product_status.advisory.id)
            {
                entry.status.push(purl_status)
            } else {
                let organization = product_status
                    .advisory
                    .find_related(organization::Entity)
                    .one(tx)
                    .await?;

                results.push(Self {
                    head: AdvisoryHead::from_advisory(
                        &product_status.advisory,
                        Memo::Provided(organization),
                        tx,
                    )
                    .await?,
                    status: vec![purl_status],
                })
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
    pub async fn from_entity<C: ConnectionTrait>(
        vuln: &vulnerability::Model,
        package_status: &purl_status::Model,
        tx: &C,
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
    pub async fn from_entities<C: ConnectionTrait>(
        entities: &[LicenseCatcher],
        tx: &C,
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

#[derive(Debug)]
pub struct ProductStatusCatcher {
    advisory: advisory::Model,
    product_status: product_status::Model,
    cpe: trustify_entity::cpe::Model,
    status: status::Model,
}

impl FromQueryResult for ProductStatusCatcher {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            advisory: Self::from_query_result_multi_model(res, "", advisory::Entity)?,
            product_status: Self::from_query_result_multi_model(res, "", product_status::Entity)?,
            cpe: Self::from_query_result_multi_model(res, "", trustify_entity::cpe::Entity)?,
            status: Self::from_query_result_multi_model(res, "", status::Entity)?,
        })
    }
}

impl FromQueryResultMultiModel for ProductStatusCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns(advisory::Entity)?
            .try_model_columns(product_status::Entity)?
            .try_model_columns(trustify_entity::cpe::Entity)?
            .try_model_columns(status::Entity)
    }
}
