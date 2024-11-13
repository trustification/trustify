use super::SbomSummary;
use crate::{
    advisory::model::AdvisoryHead,
    purl::{model::details::purl::StatusContext, model::summary::purl::PurlSummary},
    sbom::{model::SbomPackage, service::sbom::QueryCatcher, service::SbomService},
    Error,
};
use async_graphql::SimpleObject;
use cpe::uri::OwnedUri;
use sea_orm::{
    DbErr, EntityTrait, FromQueryResult, JoinType, ModelTrait, QueryFilter, QueryOrder,
    QueryResult, QuerySelect, RelationTrait, Select,
};
use sea_query::{Asterisk, Expr, Func, SimpleExpr};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};
use trustify_common::{
    cpe::CpeCompare,
    db::{
        multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        ConnectionOrTransaction, VersionMatches,
    },
    memo::Memo,
};
use trustify_entity::{
    advisory, base_purl, product, product_status, product_version, purl_status,
    qualified_purl::{self},
    sbom::{self},
    sbom_node, sbom_package, sbom_package_purl_ref, status, version_range, versioned_purl,
};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomDetails {
    #[serde(flatten)]
    pub summary: SbomSummary,

    pub advisories: Vec<SbomAdvisory>,
}

impl SbomDetails {
    /// turn an (sbom, sbom_node) row into an [`SbomDetails`], if possible
    pub async fn from_entity(
        (sbom, node): (sbom::Model, Option<sbom_node::Model>),
        service: &SbomService,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Option<SbomDetails>, Error> {
        let relevant_advisory_info = sbom
            .find_related(sbom_package::Entity)
            .join(JoinType::Join, sbom_package::Relation::Node.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
            .join(
                JoinType::LeftJoin,
                sbom_package_purl_ref::Relation::Purl.def(),
            )
            .join(
                JoinType::LeftJoin,
                qualified_purl::Relation::VersionedPurl.def(),
            )
            .filter(SimpleExpr::FunctionCall(
                Func::cust(VersionMatches)
                    .arg(Expr::col((
                        versioned_purl::Entity,
                        versioned_purl::Column::Version,
                    )))
                    .arg(Expr::col((version_range::Entity, Asterisk))),
            ))
            .join(JoinType::LeftJoin, versioned_purl::Relation::BasePurl.def())
            .join(JoinType::Join, base_purl::Relation::PurlStatus.def())
            .join(JoinType::Join, purl_status::Relation::Status.def())
            .join(
                JoinType::LeftJoin,
                purl_status::Relation::VersionRange.def(),
            )
            .join(JoinType::LeftJoin, purl_status::Relation::ContextCpe.def())
            .join(JoinType::Join, purl_status::Relation::Advisory.def())
            .join(JoinType::Join, purl_status::Relation::Vulnerability.def())
            .select_only()
            .try_into_multi_model::<QueryCatcher>()?
            .all(tx)
            .await?;

        let product_advisory_info = sbom
            .find_related(product_version::Entity)
            .join(JoinType::LeftJoin, product_version::Relation::Product.def())
            .join(JoinType::LeftJoin, product::Relation::Cpe.def())
            .join(
                JoinType::Join,
                trustify_entity::cpe::Relation::ProductStatus.def(),
            )
            .join(JoinType::Join, product_status::Relation::Status.def())
            .join(JoinType::Join, product_status::Relation::Advisory.def())
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

        let product_advisory_statuses = product_advisory_info
            .try_into_multi_model::<ProductStatusCatcher>()?
            .all(tx)
            .await?;

        let summary = SbomSummary::from_entity((sbom, node), service, tx).await?;

        Ok(match summary {
            Some(summary) => Some(SbomDetails {
                summary: summary.clone(),
                advisories: SbomAdvisory::from_models(
                    &summary.clone().described_by,
                    &relevant_advisory_info,
                    &product_advisory_statuses,
                    tx,
                )
                .await?,
            }),
            None => None,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<SbomStatus>,
}

impl SbomAdvisory {
    pub async fn from_models(
        described_by: &[SbomPackage],
        statuses: &[QueryCatcher],
        product_statuses: &[ProductStatusCatcher],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut advisories = HashMap::new();

        let sbom_cpes = described_by
            .iter()
            .flat_map(|each| each.cpe.iter())
            .flat_map(|e| {
                let e = e.replace(":*:", "::");
                let e = e.replace(":*", "");
                let result = cpe::uri::Uri::parse(&e);
                result.ok().map(|wfn| wfn.as_uri().to_owned())
            })
            .collect::<Vec<_>>();

        'status: for each in statuses {
            let status_cpe = if let Some(status_cpe) = &each.context_cpe {
                let status_cpe: Result<OwnedUri, _> = status_cpe.try_into();
                if let Ok(status_cpe) = status_cpe {
                    if sbom_cpes
                        .iter()
                        .any(|sbom_cpe| status_cpe.is_superset(sbom_cpe))
                    {
                        // status context is applicable, keep truckin'
                    } else {
                        // status context excludes this one, skip over
                        continue 'status;
                    }
                    Some(status_cpe)
                } else {
                    None
                }
            } else {
                None
            };

            // if we got here, then there's either no context or the context matches this SBOM
            let advisory = if let Some(advisory) = advisories.get_mut(&each.advisory.id) {
                advisory
            } else {
                advisories.insert(
                    each.advisory.id,
                    SbomAdvisory {
                        head: AdvisoryHead::from_advisory(&each.advisory, Memo::NotProvided, tx)
                            .await?,
                        status: vec![],
                    },
                );

                advisories
                    .get_mut(&each.advisory.id)
                    .ok_or(Error::Data("Failed to build advisories".to_string()))?
            };

            let sbom_status = if let Some(status) = advisory.status.iter_mut().find(|status| {
                if status.status == each.status.slug
                    && status.vulnerability_id == each.vulnerability.id
                {
                    match (&status.context, &status_cpe) {
                        (Some(StatusContext::Cpe(context_cpe)), Some(status_cpe)) => {
                            *context_cpe == status_cpe.to_string()
                        }
                        (None, None) => true,
                        _ => false,
                    }
                } else {
                    false
                }
            }) {
                status
            } else {
                let status = SbomStatus {
                    vulnerability_id: each.vulnerability.id.clone(),
                    status: each.status.slug.clone(),
                    context: status_cpe
                        .as_ref()
                        .map(|e| StatusContext::Cpe(e.to_string())),
                    packages: vec![],
                };
                advisory.status.push(status);
                if let Some(status) = advisory.status.last_mut() {
                    status
                } else {
                    return Err(Error::Data("failed to build advisory status".to_string()));
                }
            };

            sbom_status.packages.push(SbomPackage {
                id: each.sbom_package.node_id.clone(),
                name: each.sbom_node.name.clone(),
                version: each.sbom_package.version.clone(),
                purl: vec![
                    PurlSummary::from_entity(
                        &each.base_purl,
                        &each.versioned_purl,
                        &each.qualified_purl,
                        tx,
                    )
                    .await?,
                ],
                cpe: vec![],
            });
        }

        for product in product_statuses {
            let advisory_cpe: Option<OwnedUri> = (&product.cpe).try_into().ok();

            let mut packages = vec![];
            if let Some(package) = &product.product_status.package {
                let package = SbomPackage {
                    name: package.to_string(),
                    ..Default::default()
                };
                packages.push(package);
            }

            let status = SbomStatus {
                vulnerability_id: product.product_status.vulnerability_id.clone(),
                status: product.status.slug.clone(),
                context: advisory_cpe
                    .as_ref()
                    .map(|e| StatusContext::Cpe(e.to_string())),
                packages, // TODO find purls based on package names
            };

            match advisories.entry(product.advisory.id) {
                Entry::Occupied(entry) => entry.into_mut().status.push(status.clone()),
                Entry::Vacant(entry) => {
                    let advisory = SbomAdvisory {
                        head: AdvisoryHead::from_advisory(&product.advisory, Memo::NotProvided, tx)
                            .await?,
                        status: vec![status.clone()],
                    };
                    entry.insert(advisory.clone());
                }
            }
        }

        Ok(advisories.values().cloned().collect::<Vec<_>>())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, SimpleObject)]
#[graphql(concrete(name = "SbomStatus", params()))]
pub struct SbomStatus {
    pub vulnerability_id: String,
    pub status: String,
    #[graphql(skip)]
    pub context: Option<StatusContext>,
    pub packages: Vec<SbomPackage>,
}

impl SbomStatus {}

#[derive(Debug)]
#[allow(dead_code)] //TODO sbom field is not used at the moment, but we will probably need it for graph search
pub struct ProductStatusCatcher {
    advisory: advisory::Model,
    product_status: product_status::Model,
    cpe: trustify_entity::cpe::Model,
    status: status::Model,
    sbom: Option<sbom::Model>,
}

impl FromQueryResult for ProductStatusCatcher {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            advisory: Self::from_query_result_multi_model(res, "", advisory::Entity)?,
            product_status: Self::from_query_result_multi_model(res, "", product_status::Entity)?,
            cpe: Self::from_query_result_multi_model(res, "", trustify_entity::cpe::Entity)?,
            status: Self::from_query_result_multi_model(res, "", status::Entity)?,
            sbom: Self::from_query_result_multi_model_optional(res, "", sbom::Entity)?,
        })
    }
}

impl FromQueryResultMultiModel for ProductStatusCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns(advisory::Entity)?
            .try_model_columns(product_status::Entity)?
            .try_model_columns(trustify_entity::cpe::Entity)?
            .try_model_columns(status::Entity)?
            .try_model_columns(product_version::Entity)?
            .try_model_columns(sbom::Entity)
    }
}
