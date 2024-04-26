use crate::graph::advisory::AdvisoryInformation;
use crate::graph::Graph;
use crate::service::{
    advisory::osv::schema::{Event, Package, SeverityType, Vulnerability},
    hashing::HashingRead,
    Error,
};
use std::io::Read;
use std::str::FromStr;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::Cvss3Base;

pub struct OsvLoader<'g> {
    graph: &'g Graph,
}

impl<'g> OsvLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<L: Into<String>, R: Read>(
        &self,
        location: L,
        record: R,
        checksum: &str,
    ) -> Result<String, Error> {
        let mut reader = HashingRead::new(record);
        let osv: Vulnerability = serde_json::from_reader(&mut reader)?;

        let advisory_id = osv.id.clone();

        let tx = self.graph.transaction().await?;

        if let Some(cve_ids) = &osv.aliases.map(|aliases| {
            aliases
                .iter()
                .filter(|e| e.starts_with("CVE-"))
                .cloned()
                .collect::<Vec<_>>()
        }) {
            let digests = reader.finish().map_err(|e| Error::Generic(e.into()))?;
            let encoded_sha256 = hex::encode(digests.sha256);
            if checksum != encoded_sha256 {
                return Err(Error::Storage(anyhow::Error::msg(
                    "document integrity check failed",
                )));
            }

            let information = AdvisoryInformation {
                title: osv.summary.clone(),
                published: Some(osv.published),
                modified: Some(osv.modified),
            };
            let advisory = self
                .graph
                .ingest_advisory(&osv.id, location, encoded_sha256, information, &tx)
                .await?;

            if let Some(withdrawn) = osv.withdrawn {
                advisory.set_withdrawn_at(withdrawn, &tx).await?;
            }

            for cve_id in cve_ids {
                let advisory_vuln = advisory.link_to_vulnerability(cve_id, &tx).await?;

                for severity in osv.severity.iter().flatten() {
                    if matches!(severity.severity_type, SeverityType::CVSSv3) {
                        match Cvss3Base::from_str(&severity.score) {
                            Ok(cvss3) => {
                                advisory_vuln.ingest_cvss3_score(cvss3, &tx).await?;
                            }
                            Err(err) => {
                                log::warn!("Unable to parse CVSS3: {:#?}", err);
                            }
                        }
                    }
                }

                for affected in &osv.affected {
                    if let Some(package) = &affected.package {
                        match package {
                            Package::Named { .. } => {
                                todo!()
                            }
                            Package::Purl { purl } => {
                                if let Ok(purl) = Purl::from_str(purl) {
                                    for range in affected.ranges.iter().flatten() {
                                        let parsed_range = events_to_range(&range.events);
                                        if let (Some(start), Some(end)) = &parsed_range {
                                            advisory_vuln
                                                .ingest_affected_package_range(
                                                    &purl, start, end, &tx,
                                                )
                                                .await?;
                                        }

                                        if let (_, Some(fixed)) = &parsed_range {
                                            let mut fixed_purl = purl.clone();
                                            fixed_purl.version = Some(fixed.clone());

                                            advisory_vuln
                                                .ingest_fixed_package_version(&fixed_purl, &tx)
                                                .await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tx.commit().await?;
        Ok(advisory_id)
    }
}

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
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;

    use test_context::test_context;
    use test_log::test;
    use trustify_common::{advisory::Assertion, db::test::TrustifyContext};

    use crate::graph::Graph;
    use trustify_common::db::Transactional;

    use crate::service::advisory::osv::loader::OsvLoader;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn loader(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../../etc/test-data/osv");

        let osv_json = test_data.join("RUSTSEC-2021-0079.json");
        let osv_file = File::open(osv_json)?;
        let checksum = "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51";

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph.get_advisory(checksum, Transactional::None).await?;

        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);

        loader
            .load("RUSTSEC-2021-0079.json", osv_file, checksum)
            .await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph.get_advisory(checksum, Transactional::None).await?;

        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();
        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(()).await?;
        assert_eq!(1, loaded_advisory_vulnerabilities.len());
        let loaded_advisory_vulnerability = &loaded_advisory_vulnerabilities[0];

        let affected_assertions = loaded_advisory_vulnerability
            .affected_assertions(())
            .await?;

        assert_eq!(1, affected_assertions.assertions.len());

        let affected_assertion = affected_assertions.assertions.get("pkg://cargo/hyper");
        assert!(affected_assertion.is_some());

        let affected_assertion = &affected_assertion.unwrap()[0];

        assert!(
            matches!( affected_assertion, Assertion::Affected {start_version,end_version}
                if start_version == "0.0.0-0"
                && end_version == "0.14.10"
            )
        );

        let fixed_assertions = loaded_advisory_vulnerability.fixed_assertions(()).await?;

        assert_eq!(1, fixed_assertions.assertions.len());

        let fixed_assertion = fixed_assertions.assertions.get("pkg://cargo/hyper");
        assert!(fixed_assertion.is_some());

        let fixed_assertion = fixed_assertion.unwrap();
        assert_eq!(1, fixed_assertion.len());

        let fixed_assertion = &fixed_assertion[0];

        assert!(matches!( fixed_assertion, Assertion::Fixed{version }
            if version == "0.14.10"
        ));

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
