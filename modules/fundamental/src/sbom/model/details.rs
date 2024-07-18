use crate::advisory::model::AdvisoryHead;
use crate::purl::model::details::purl::StatusContext;
use crate::purl::model::summary::purl::PurlSummary;
use crate::sbom::model::{SbomHead, SbomPackage};
use crate::sbom::service::sbom::QueryCatcher;
use crate::Error;
use cpe::uri::OwnedUri;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use trustify_common::cpe::CpeCompare;
use trustify_common::db::ConnectionOrTransaction;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomDetails {
    #[serde(flatten)]
    pub head: SbomHead,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub described_by: Vec<SbomPackage>,
    pub advisories: Vec<SbomAdvisory>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomAdvisory {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
                        head: AdvisoryHead::from_advisory(&each.advisory, None, tx).await?,
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

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SbomStatus {
    pub vulnerability_id: String,
    pub status: String,
    pub context: Option<StatusContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<SbomPackage>,
}

impl SbomStatus {}
