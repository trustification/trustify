use super::SbomSummary;
use crate::{
    advisory::model::AdvisoryHead,
    purl::model::{details::purl::StatusContext, summary::purl::PurlSummary},
    sbom::{
        model::SbomPackage,
        service::{sbom::QueryCatcher, SbomService},
    },
    vulnerability::model::VulnerabilityHead,
    Error,
};
use cpe::{cpe::Cpe, uri::OwnedUri};
use sea_orm::{
    ConnectionTrait, DbErr, EntityTrait, FromQueryResult, Iden, JoinType, ModelTrait, QueryFilter,
    QueryOrder, QueryResult, QuerySelect, RelationTrait, Select,
};
use sea_query::{Asterisk, Expr, Func, SimpleExpr};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use trustify_common::{
    cpe::CpeCompare,
    db::{
        multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        VersionMatches,
    },
    memo::Memo,
};
use trustify_cvss::cvss3::{score::Score, severity::Severity, Cvss3Base};
use trustify_entity::{
    advisory, base_purl, cvss3, product, product_status, product_version, purl_status,
    qualified_purl, sbom, sbom_node, sbom_package, sbom_package_purl_ref, status, version_range,
    versioned_purl, vulnerability,
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
    pub async fn from_entity<C: ConnectionTrait>(
        (sbom, node): (sbom::Model, Option<sbom_node::Model>),
        service: &SbomService,
        tx: &C,
    ) -> Result<Option<SbomDetails>, Error> {
        let mut relevant_advisory_info = sbom
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

        let mut product_advisory_info = sbom
            .find_related(product_version::Entity)
            .join(JoinType::LeftJoin, product_version::Relation::Product.def())
            .join(JoinType::LeftJoin, product::Relation::Cpe.def())
            .join(
                JoinType::Join,
                trustify_entity::cpe::Relation::ProductStatus.def(),
            )
            .join(JoinType::Join, product_status::Relation::Status.def())
            .join(JoinType::Join, product_status::Relation::Advisory.def())
            .join(
                JoinType::Join,
                product_status::Relation::Vulnerability.def(),
            )
            // Joins for purl-related tables
            .join(JoinType::Join, sbom::Relation::Node.def())
            .join(JoinType::Join, sbom_node::Relation::Package.def())
            .join(JoinType::Join, sbom_package::Relation::Purl.def())
            .join(JoinType::Join, sbom_package_purl_ref::Relation::Purl.def())
            .join(
                JoinType::Join,
                qualified_purl::Relation::VersionedPurl.def(),
            )
            .join(JoinType::Join, versioned_purl::Relation::BasePurl.def())
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
            .order_by_asc(product_status::Column::VulnerabilityId)
            // Filter for product_status.package
            .filter(
                Expr::col((product_status::Entity, product_status::Column::Package))
                    .is_null()
                    .or(Expr::col((product_status::Entity, product_status::Column::Package)).eq(""))
                    .or(SimpleExpr::Binary(
                        Box::new(
                            Expr::col((product_status::Entity, product_status::Column::Package))
                                .into(),
                        ),
                        sea_query::BinOper::Like,
                        Box::new(SimpleExpr::FunctionCall(
                            Func::cust(CustomFunc::Concat).args([
                                Expr::col((base_purl::Entity, base_purl::Column::Namespace)).into(),
                                Expr::val("/").into(),
                                Expr::col((base_purl::Entity, base_purl::Column::Name)).into(),
                            ]),
                        )),
                    ))
                    .or(
                        Expr::col((product_status::Entity, product_status::Column::Package))
                            .eq(Expr::col((base_purl::Entity, base_purl::Column::Name))),
                    ),
            )
            .select_only()
            .try_into_multi_model::<QueryCatcher>()?
            .all(tx)
            .await?;

        relevant_advisory_info.append(&mut product_advisory_info);

        let summary = SbomSummary::from_entity((sbom, node), service, tx).await?;

        Ok(match summary {
            Some(summary) => Some(SbomDetails {
                summary: summary.clone(),
                advisories: SbomAdvisory::from_models(
                    &summary.described_by,
                    &relevant_advisory_info,
                    tx,
                )
                .await?,
            }),
            None => None,
        })
    }
}

#[derive(Iden)]
enum CustomFunc {
    #[iden = "CONCAT"]
    Concat,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub status: Vec<SbomStatus>,
}

impl SbomAdvisory {
    pub async fn from_models<C: ConnectionTrait>(
        described_by: &[SbomPackage],
        statuses: &[QueryCatcher],
        tx: &C,
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
                    if sbom_cpes.iter().any(|sbom_cpe| {
                        let status_version = status_cpe.version().to_string();
                        let sbom_version = sbom_cpe.version().to_string();
                        // This is a bit simplified logic, but it is tune with v1 parity.
                        // We need to investigate this more and apply proper version matching in the future
                        status_cpe.is_superset(sbom_cpe)
                            || status_version == "*"
                            || sbom_version.starts_with(&status_version)
                    }) {
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
                    && status.vulnerability.identifier == each.vulnerability.id
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
                let status = SbomStatus::new(
                    &each.vulnerability,
                    each.status.slug.clone(),
                    status_cpe,
                    vec![],
                    tx,
                )
                .await?;
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

        Ok(advisories.values().cloned().collect::<Vec<_>>())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomStatus {
    #[serde(flatten)]
    pub vulnerability: VulnerabilityHead,
    pub average_severity: Severity,
    pub status: String,
    pub context: Option<StatusContext>,
    pub packages: Vec<SbomPackage>,
}

impl SbomStatus {
    pub async fn new<C: ConnectionTrait>(
        vulnerability: &vulnerability::Model,
        status: String,
        cpe: Option<OwnedUri>,
        packages: Vec<SbomPackage>,
        tx: &C,
    ) -> Result<Self, Error> {
        let cvss3 = vulnerability.find_related(cvss3::Entity).all(tx).await?;
        let average_severity = Score::from_iter(cvss3.iter().map(Cvss3Base::from)).severity();
        Ok(Self {
            vulnerability: VulnerabilityHead::from_vulnerability_entity(
                vulnerability,
                Memo::NotProvided,
                tx,
            )
            .await?,
            context: cpe.as_ref().map(|e| StatusContext::Cpe(e.to_string())),
            average_severity,
            status,
            packages,
        })
    }
    pub fn identifier(&self) -> &str {
        &self.vulnerability.identifier
    }
}

#[derive(Debug)]
#[allow(dead_code)] //TODO sbom field is not used at the moment, but we will probably need it for graph search
pub struct ProductStatusCatcher {
    advisory: advisory::Model,
    vulnerability: trustify_entity::vulnerability::Model,
    product_status: product_status::Model,
    cpe: trustify_entity::cpe::Model,
    status: status::Model,
    sbom: Option<sbom::Model>,
    base_purl: base_purl::Model,
    versioned_purl: versioned_purl::Model,
    qualified_purl: qualified_purl::Model,
    sbom_package: sbom_package::Model,
    sbom_node: sbom_node::Model,
}

impl FromQueryResult for ProductStatusCatcher {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            advisory: Self::from_query_result_multi_model(res, "", advisory::Entity)?,
            vulnerability: Self::from_query_result_multi_model(
                res,
                "",
                trustify_entity::vulnerability::Entity,
            )?,
            product_status: Self::from_query_result_multi_model(res, "", product_status::Entity)?,
            cpe: Self::from_query_result_multi_model(res, "", trustify_entity::cpe::Entity)?,
            status: Self::from_query_result_multi_model(res, "", status::Entity)?,
            sbom: Self::from_query_result_multi_model_optional(res, "", sbom::Entity)?,
            base_purl: Self::from_query_result_multi_model(res, "", base_purl::Entity)?,
            versioned_purl: Self::from_query_result_multi_model(res, "", versioned_purl::Entity)?,
            qualified_purl: Self::from_query_result_multi_model(res, "", qualified_purl::Entity)?,
            sbom_package: Self::from_query_result_multi_model(res, "", sbom_package::Entity)?,
            sbom_node: Self::from_query_result_multi_model(res, "", sbom_node::Entity)?,
        })
    }
}

impl FromQueryResultMultiModel for ProductStatusCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns(advisory::Entity)?
            .try_model_columns(trustify_entity::vulnerability::Entity)?
            .try_model_columns(product_status::Entity)?
            .try_model_columns(trustify_entity::cpe::Entity)?
            .try_model_columns(status::Entity)?
            .try_model_columns(product_version::Entity)?
            .try_model_columns(base_purl::Entity)?
            .try_model_columns(versioned_purl::Entity)?
            .try_model_columns(qualified_purl::Entity)?
            .try_model_columns(sbom_package::Entity)?
            .try_model_columns(sbom_node::Entity)
    }
}
