use crate::{
    graph::{
        Graph,
        advisory::{
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
            version::{Version, VersionInfo, VersionSpec},
        },
        vulnerability::VulnerabilityInformation,
    },
    model::IngestResult,
    service::{Error, advisory::cve::divination::divine_purl},
};
use cve::{
    Cve, Timestamp,
    common::{Description, Product, Status, VersionRange},
};
use sea_orm::TransactionTrait;
use std::fmt::Debug;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id};
use trustify_entity::{labels::Labels, version_scheme::VersionScheme};

/// Loader capable of parsing a CVE Record JSON file
/// and manipulating the Graph to integrate it into
/// the knowledge base.
///
/// Should result in ensuring that a *vulnerability*
/// related to the CVE Record exists in the fetch, _along with_
/// also ensuring that the CVE *advisory* ends up also
/// in the fetch.
pub struct CveLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CveLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, cve), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        cve: Cve,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let id = cve.id();
        let labels = labels.into().add("type", "cve");

        let tx = self.graph.db.begin().await?;

        let VulnerabilityDetails {
            org_name,
            descriptions,
            assigned,
            affected,
            information,
        } = Self::extract_vuln_info(&cve);

        let cwes = information.cwes.clone();
        let release_date = information.published;
        let reserved_date = information.reserved;
        let title = information.title.clone();
        let advisory_info = AdvisoryInformation {
            id: id.to_string(),
            title: information.title.clone(),
            // TODO: check if we have some kind of version information
            version: None,
            issuer: org_name.map(ToString::to_string),
            published: information.published,
            modified: information.modified,
            withdrawn: information.withdrawn,
        };

        let vulnerability = self
            .graph
            .ingest_vulnerability(id, information, &tx)
            .await?;

        let entries = Self::build_descriptions(descriptions);
        let english_description = Self::find_best_description_for_title(descriptions);

        let advisory = self
            .graph
            .ingest_advisory(id, labels, digests, advisory_info, &tx)
            .await?;

        // Link the advisory to the backing vulnerability
        let advisory_vuln = advisory
            .link_to_vulnerability(
                id,
                Some(AdvisoryVulnerabilityInformation {
                    title,
                    summary: None,
                    description: english_description.map(ToString::to_string),
                    reserved_date,
                    discovery_date: assigned,
                    release_date,
                    cwes,
                }),
                &tx,
            )
            .await?;

        if let Some(affected) = affected {
            for product in affected {
                if let Some(purl) = divine_purl(product) {
                    // okay! we have a purl, now
                    // sort out version bounds & status
                    for version in &product.versions {
                        let (version_spec, version_type, status) = match version {
                            cve::common::Version::Single(version) => (
                                VersionSpec::Exact(version.version.clone()),
                                version.version_type.clone(),
                                &version.status,
                            ),
                            cve::common::Version::Range(range) => match &range.range {
                                VersionRange::LessThan(upper) => (
                                    VersionSpec::Range(
                                        Version::Inclusive(range.version.clone()),
                                        Version::Exclusive(upper.clone()),
                                    ),
                                    Some(range.version_type.clone()),
                                    &range.status,
                                ),
                                VersionRange::LessThanOrEqual(upper) => (
                                    VersionSpec::Range(
                                        Version::Inclusive(range.version.clone()),
                                        Version::Inclusive(upper.clone()),
                                    ),
                                    Some(range.version_type.clone()),
                                    &range.status,
                                ),
                            },
                        };

                        advisory_vuln
                            .ingest_package_status(
                                None,
                                &purl,
                                match status {
                                    Status::Affected => "affected",
                                    Status::Unaffected => "not_affected",
                                    Status::Unknown => "unknown",
                                },
                                VersionInfo {
                                    scheme: version_type
                                        .as_deref()
                                        .map(VersionScheme::from)
                                        .unwrap_or(VersionScheme::Generic),
                                    spec: version_spec,
                                },
                                &tx,
                            )
                            .await?
                    }
                }
            }
        }

        vulnerability
            .drop_descriptions_for_advisory(advisory.advisory.id, &tx)
            .await?;

        vulnerability
            .add_descriptions(advisory.advisory.id, entries, &tx)
            .await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: Some(id.to_string()),
            warnings: vec![],
        })
    }

    /// Build descriptions
    fn build_descriptions(descriptions: &[Description]) -> Vec<(&str, &str)> {
        descriptions
            .iter()
            .map(|desc| (desc.language.as_str(), desc.value.as_str()))
            .collect()
    }

    /// Quicker version to find the best description as an alternative when not having a title.
    fn find_best_description_for_title(descriptions: &[Description]) -> Option<&str> {
        descriptions
            .iter()
            .find(|desc| matches!(desc.language.as_str(), "en-US" | "en_US"))
            .or_else(|| descriptions.iter().find(|desc| desc.language == "en"))
            .map(|desc| desc.value.as_str())
    }

    fn extract_vuln_info(cve: &Cve) -> VulnerabilityDetails {
        let reserved = cve
            .common_metadata()
            .date_reserved
            .map(Timestamp::assume_utc);
        let published = cve
            .common_metadata()
            .date_published
            .map(Timestamp::assume_utc);
        let modified = cve
            .common_metadata()
            .date_updated
            .map(Timestamp::assume_utc);

        let (title, assigned, withdrawn, descriptions, cwe, org_name, affected) = match &cve {
            Cve::Rejected(rejected) => (
                None,
                None,
                rejected.metadata.date_rejected.map(Timestamp::assume_utc),
                &rejected.containers.cna.rejected_reasons,
                None,
                rejected
                    .containers
                    .cna
                    .common
                    .provider_metadata
                    .short_name
                    .as_deref(),
                None,
            ),
            Cve::Published(published) => (
                published
                    .containers
                    .cna
                    .title
                    .as_deref()
                    .or_else(|| {
                        Self::find_best_description_for_title(
                            &published.containers.cna.descriptions,
                        )
                    })
                    .map(ToString::to_string),
                published
                    .containers
                    .cna
                    .date_assigned
                    .map(Timestamp::assume_utc),
                None,
                &published.containers.cna.descriptions,
                {
                    let cwes = published
                        .containers
                        .cna
                        .problem_types
                        .iter()
                        .flat_map(|pt| pt.descriptions.iter())
                        .flat_map(|desc| desc.cwe_id.clone())
                        .collect::<Vec<_>>();
                    if cwes.is_empty() { None } else { Some(cwes) }
                },
                published
                    .containers
                    .cna
                    .common
                    .provider_metadata
                    .short_name
                    .as_deref(),
                Some(&published.containers.cna.affected),
            ),
        };

        VulnerabilityDetails {
            org_name,
            descriptions,
            assigned,
            affected,
            information: VulnerabilityInformation {
                title: title.clone(),
                reserved,
                published,
                modified,
                withdrawn,
                cwes: cwe,
            },
        }
    }
}

struct VulnerabilityDetails<'a> {
    pub org_name: Option<&'a str>,
    pub descriptions: &'a Vec<Description>,
    pub assigned: Option<OffsetDateTime>,
    pub affected: Option<&'a Vec<Product>>,
    pub information: VulnerabilityInformation,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::graph::Graph;
    use hex::ToHex;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use time::macros::datetime;
    use trustify_common::purl::Purl;
    use trustify_test_context::{TrustifyContext, document};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn cve_loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());

        let (cve, digests): (Cve, _) = document("mitre/CVE-2024-28111.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", &ctx.db).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);
        loader
            .load(("file", "CVE-2024-28111.json"), cve, &digests)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", &ctx.db).await?;
        assert!(loaded_vulnerability.is_some());
        let loaded_vulnerability = loaded_vulnerability.unwrap();
        assert_eq!(
            loaded_vulnerability.vulnerability.reserved,
            Some(datetime!(2024-03-04 14:19:14.059 UTC))
        );

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), &ctx.db)
            .await?;
        assert!(loaded_advisory.is_some());

        let descriptions = loaded_vulnerability.descriptions("en", &ctx.db).await?;
        assert_eq!(1, descriptions.len());
        assert!(
            descriptions[0]
                .starts_with("Canarytokens helps track activity and actions on a network")
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn divine_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());

        let (cve, digests): (Cve, _) = document("cve/CVE-2024-26308.json").await?;

        let loader = CveLoader::new(&graph);
        loader
            .load(("file", "CVE-2024-26308.json"), cve, &digests)
            .await?;

        let purl = graph
            .get_package(
                &Purl::from_str("pkg:maven/org.apache.commons/commons-compress")?,
                &ctx.db,
            )
            .await?;

        assert!(purl.is_some());

        let purl = purl.unwrap();
        let purl = purl.base_purl;

        assert_eq!(purl.r#type, "maven");
        assert_eq!(purl.namespace, Some("org.apache.commons".to_string()));
        assert_eq!(purl.name, "commons-compress");

        Ok(())
    }
}
