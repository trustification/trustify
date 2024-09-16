use super::SbomSummary;
use crate::{
    advisory::model::AdvisoryHead,
    purl::{model::details::purl::StatusContext, model::summary::purl::PurlSummary},
    sbom::{model::SbomPackage, service::sbom::QueryCatcher, service::SbomService},
    Error,
};
use async_graphql::SimpleObject;
use cpe::uri::OwnedUri;
use sea_orm::{JoinType, ModelTrait, QuerySelect, RelationTrait};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use trustify_common::db::multi_model::SelectIntoMultiModel;
use trustify_common::{cpe::CpeCompare, db::ConnectionOrTransaction, memo::Memo};
use trustify_entity::{
    base_purl, purl_status,
    qualified_purl::{self},
    sbom::{self},
    sbom_node, sbom_package, sbom_package_purl_ref, versioned_purl,
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

        let summary = SbomSummary::from_entity((sbom, node), service, tx).await?;

        Ok(match summary {
            Some(summary) => Some(SbomDetails {
                summary: summary.clone(),
                advisories: SbomAdvisory::from_models(
                    &summary.clone().described_by,
                    &relevant_advisory_info,
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
