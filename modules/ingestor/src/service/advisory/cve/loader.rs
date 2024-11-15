use crate::{
    graph::{
        advisory::{
            advisory_vulnerability::{Version, VersionInfo, VersionSpec},
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
        },
        vulnerability::VulnerabilityInformation,
        Graph,
    },
    model::IngestResult,
    service::{advisory::cve::divination::divine_purl, Error},
};
use cve::{
    common::{Description, Product, Status, VersionRange},
    Cve, Timestamp,
};
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

const DESCRIPTION_EN: &str = "en";

impl<'g> CveLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, cve), ret)]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        cve: Cve,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let id = cve.id();
        let labels = labels.into().add("type", "cve");

        let tx = self.graph.transaction().await?;

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

        let (entries, english_description) = Self::build_descriptions(descriptions);

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
                                        .and_then(|version_type| {
                                            try_from_cve_version_scheme(&version_type).ok()
                                        })
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
            document_id: id.to_string(),
            warnings: vec![],
        })
    }

    /// Build descriptions,
    fn build_descriptions(descriptions: &[Description]) -> (Vec<(&str, &str)>, Option<&str>) {
        let mut english_description = None;
        let mut entries = Vec::<(&str, &str)>::new();

        for description in descriptions {
            entries.push((&description.language, &description.value));
            if description.language == DESCRIPTION_EN {
                english_description = Some(&*description.value);
            }
        }

        (entries, english_description)
    }

    /// Quicker version to find the best description as an alternative when not having a title.
    fn find_best_description_for_title(descriptions: &[Description]) -> Option<&str> {
        // Currently, we simply choose the first english description.
        descriptions
            .iter()
            .find(|desc| desc.language == DESCRIPTION_EN)
            .map(|desc| &*desc.value)
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
                    if cwes.is_empty() {
                        None
                    } else {
                        Some(cwes)
                    }
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
                cwes: cwe.clone(),
            },
        }
    }
}

/// Translate from a CVE project version type to our internal version scheme.
///
/// Also see: <https://github.com/CVEProject/cve-schema/blob/6af5c9c49c5b62e7b1f46756e1f3aef328848e1c/schema/CVE_Record_Format.json#L306-L318>
///
/// However, the reality looks quite weird. The following command can be run to get an overview of
/// what the current state holds. Run from the `cves` directory of the repository from:
/// <https://github.com/CVEProject/cvelistV5>
///
/// ```bash
/// find -name "CVE-*.json" -exec jq '.containers.cna.affected?[]?.versions?[]?.versionType | select (. != null )' {} \; | sort -u
/// ```
fn try_from_cve_version_scheme(scheme: &str) -> Result<VersionScheme, ()> {
    Ok(match scheme {
        "commit" | "git" => VersionScheme::Git,
        "custom" => VersionScheme::Generic,
        "maven" => VersionScheme::Maven,
        "npm" => VersionScheme::Semver,
        "python" => VersionScheme::Python,
        "rpm" => VersionScheme::Rpm,
        "semver" => VersionScheme::Semver,
        _ => return Err(()),
    })
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
    use trustify_common::db::Transactional;
    use trustify_common::purl::Purl;
    use trustify_test_context::{document, TrustifyContext};

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn cve_loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());

        let (cve, digests): (Cve, _) = document("mitre/CVE-2024-28111.json").await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", ()).await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = CveLoader::new(&graph);
        loader
            .load(("file", "CVE-2024-28111.json"), cve, &digests)
            .await?;

        let loaded_vulnerability = graph.get_vulnerability("CVE-2024-28111", ()).await?;
        assert!(loaded_vulnerability.is_some());
        let loaded_vulnerability = loaded_vulnerability.unwrap();
        assert_eq!(
            loaded_vulnerability.vulnerability.reserved,
            Some(datetime!(2024-03-04 14:19:14.059 UTC))
        );

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_some());

        let descriptions = loaded_vulnerability.descriptions("en", ()).await?;
        assert_eq!(1, descriptions.len());
        assert!(descriptions[0]
            .starts_with("Canarytokens helps track activity and actions on a network"));

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
                Transactional::None,
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
