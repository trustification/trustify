use crate::{
    graph::{
        advisory::{
            advisory_vulnerability::{Version, VersionInfo, VersionSpec},
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
        },
        purl::creator::PurlCreator,
        Graph,
    },
    model::IngestResult,
    service::{advisory::osv::translate, Error, Warnings},
};
use osv::schema::{Event, ReferenceType, SeverityType, Vulnerability};
use sbom_walker::report::ReportSink;
use std::{fmt::Debug, str::FromStr, sync::OnceLock};
use tracing::instrument;
use trustify_common::{hashing::Digests, id::Id, purl::Purl, time::ChronoExt};
use trustify_cvss::cvss3::Cvss3Base;
use trustify_entity::labels::Labels;

pub struct OsvLoader<'g> {
    graph: &'g Graph,
}

impl<'g> OsvLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, osv), ret)]
    pub async fn load(
        &self,
        labels: impl Into<Labels> + Debug,
        osv: Vulnerability,
        digests: &Digests,
        issuer: Option<String>,
    ) -> Result<IngestResult, Error> {
        let warnings = Warnings::new();

        let labels = labels.into().add("type", "osv");

        let issuer = issuer.or(detect_organization(&osv));

        let tx = self.graph.transaction().await?;

        let cve_ids = osv.aliases.iter().flat_map(|aliases| {
            aliases
                .iter()
                .filter(|e| e.starts_with("CVE-"))
                .cloned()
                .collect::<Vec<_>>()
        });

        let information = AdvisoryInformation {
            title: osv.summary.clone(),
            // TODO(#899): check if we have some kind of version information
            version: None,
            issuer,
            published: Some(osv.published.into_time()),
            modified: Some(osv.modified.into_time()),
            withdrawn: osv.withdrawn.map(ChronoExt::into_time),
        };
        let advisory = self
            .graph
            .ingest_advisory(&osv.id, labels, digests, information, &tx)
            .await?;

        if let Some(withdrawn) = osv.withdrawn {
            advisory
                .set_withdrawn_at(withdrawn.into_time(), &tx)
                .await?;
        }

        let mut purl_creator = PurlCreator::new();

        for cve_id in cve_ids {
            self.graph.ingest_vulnerability(&cve_id, (), &tx).await?;

            let advisory_vuln = advisory
                .link_to_vulnerability(
                    &cve_id,
                    Some(AdvisoryVulnerabilityInformation {
                        title: osv.summary.clone(),
                        summary: osv.summary.clone(),
                        description: osv.details.clone(),
                        discovery_date: None,
                        release_date: None,
                        cwes: None,
                    }),
                    &tx,
                )
                .await?;

            for severity in osv.severity.iter().flatten() {
                if matches!(severity.severity_type, SeverityType::CVSSv3) {
                    match Cvss3Base::from_str(&severity.score) {
                        Ok(cvss3) => {
                            advisory_vuln.ingest_cvss3_score(cvss3, &tx).await?;
                        }
                        Err(err) => {
                            let msg = format!("Unable to parse CVSS3: {:#?}", err);
                            log::info!("{msg}");
                            warnings.error(msg)
                        }
                    }
                }
            }

            for affected in &osv.affected {
                // we only process it when we have a package

                let Some(package) = &affected.package else {
                    tracing::debug!(
                        osv = osv.id,
                        "OSV document did not contain an 'affected' section",
                    );
                    continue;
                };

                // extract PURLs

                let mut purls = vec![];
                purls.extend(translate::to_purl(package).map(Purl::from));
                if let Some(purl) = &package.purl {
                    purls.extend(Purl::from_str(purl).ok());
                }

                for purl in purls {
                    // iterate through the known versions, apply the version, and create them
                    for version in affected.versions.iter().flatten() {
                        let mut purl = purl.clone();
                        purl.version = Some(version.clone());
                        purl_creator.add(purl);
                    }

                    for range in affected.ranges.iter().flatten() {
                        let parsed_range = events_to_range(&range.events);

                        let spec = match &parsed_range {
                            (Some(start), None) => Some(VersionSpec::Range(
                                Version::Inclusive(start.clone()),
                                Version::Unbounded,
                            )),
                            (None, Some(end)) => Some(VersionSpec::Range(
                                Version::Unbounded,
                                Version::Exclusive(end.clone()),
                            )),
                            (Some(start), Some(end)) => Some(VersionSpec::Range(
                                Version::Inclusive(start.clone()),
                                Version::Exclusive(end.clone()),
                            )),
                            (None, None) => None,
                        };

                        if let Some(spec) = spec {
                            advisory_vuln
                                .ingest_package_status(
                                    None,
                                    &purl,
                                    "affected",
                                    VersionInfo {
                                        // TODO(#900): detect better version scheme
                                        scheme: "semver".to_string(),
                                        spec,
                                    },
                                    &tx,
                                )
                                .await?;
                        }

                        if let (_, Some(fixed)) = &parsed_range {
                            advisory_vuln
                                .ingest_package_status(
                                    None,
                                    &purl,
                                    "fixed",
                                    VersionInfo {
                                        // TODO(#900) detect better version scheme
                                        scheme: "semver".to_string(),
                                        spec: VersionSpec::Exact(fixed.clone()),
                                    },
                                    &tx,
                                )
                                .await?
                        }
                    }
                }
            }
        }

        purl_creator.create(&self.graph.connection(&tx)).await?;

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: osv.id,
            warnings: warnings.into(),
        })
    }
}

fn detect_organization(osv: &Vulnerability) -> Option<String> {
    if let Some(references) = &osv.references {
        let advisory_location = references
            .iter()
            .find(|reference| matches!(reference.reference_type, ReferenceType::Advisory));

        if let Some(advisory_location) = advisory_location {
            let url = &advisory_location.url;
            return get_well_known_prefixes().detect(url);
        }
    }
    None
}

struct PrefixMatcher {
    prefixes: Vec<PrefixMapping>,
}

impl PrefixMatcher {
    fn new() -> Self {
        Self { prefixes: vec![] }
    }

    fn add(&mut self, prefix: impl Into<String>, name: impl Into<String>) {
        self.prefixes.push(PrefixMapping {
            prefix: prefix.into(),
            name: name.into(),
        })
    }

    fn detect(&self, input: &str) -> Option<String> {
        self.prefixes
            .iter()
            .find(|each| input.starts_with(&each.prefix))
            .map(|inner| inner.name.clone())
    }
}

struct PrefixMapping {
    prefix: String,
    name: String,
}

fn get_well_known_prefixes() -> &'static PrefixMatcher {
    WELL_KNOWN_PREFIXES.get_or_init(|| {
        let mut matcher = PrefixMatcher::new();

        matcher.add(
            "https://rustsec.org/advisories/RUSTSEC",
            "Rust Security Advisory Database",
        );

        matcher
    })
}

static WELL_KNOWN_PREFIXES: OnceLock<PrefixMatcher> = OnceLock::new();

fn events_to_range(events: &[Event]) -> (Option<String>, Option<String>) {
    let start = events.iter().find_map(|e| {
        if let Event::Introduced(version) = e {
            Some(version.clone())
        } else {
            None
        }
    });

    let end = events.iter().find_map(|e| {
        if let Event::Fixed(version) = e {
            Some(version.clone())
        } else {
            None
        }
    });

    (start, end)
}

#[cfg(test)]
mod test {
    use hex::ToHex;
    use osv::schema::Vulnerability;
    use test_context::test_context;
    use test_log::test;

    use crate::graph::Graph;
    use trustify_common::db::Transactional;
    use trustify_test_context::{document, TrustifyContext};

    use crate::service::advisory::osv::loader::OsvLoader;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn loader(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let db = &ctx.db;
        let graph = Graph::new(db.clone());

        let (osv, digests): (Vulnerability, _) = document("osv/RUSTSEC-2021-0079.json").await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;
        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);
        loader
            .load(("file", "RUSTSEC-2021-0079.json"), osv, &digests, None)
            .await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(()).await?;
        assert_eq!(1, loaded_advisory_vulnerabilities.len());
        let _loaded_advisory_vulnerability = &loaded_advisory_vulnerabilities[0];

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2021-32714", ())
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(()).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
        );

        assert!(loaded_advisory
            .get_vulnerability("CVE-8675309", ())
            .await?
            .is_none());

        Ok(())
    }
}
