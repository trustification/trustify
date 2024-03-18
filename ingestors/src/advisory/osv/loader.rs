use std::io::Read;
use std::str::FromStr;
use trustify_common::purl::Purl;

use trustify_graph::graph::Graph;

use crate::advisory::osv::schema::{Event, Package, Vulnerability};
use crate::hashing::HashingRead;
use crate::Error;

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
    ) -> Result<(), Error> {
        let mut reader = HashingRead::new(record);
        let osv: Vulnerability = serde_json::from_reader(&mut reader)?;

        let tx = self.graph.transaction().await?;

        if let Some(cve_ids) = &osv.aliases.map(|aliases| {
            aliases
                .iter()
                .filter(|e| e.starts_with("CVE-"))
                .cloned()
                .collect::<Vec<_>>()
        }) {
            let hashes = reader.hashes();
            let sha256 = hex::encode(hashes.sha256.as_ref());

            let advisory = self
                .graph
                .ingest_advisory(osv.id, location, sha256, &tx)
                .await?;

            for cve_id in cve_ids {
                let advisory_vuln = advisory.link_to_vulnerability(cve_id, &tx).await?;

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
                                                    purl.clone(),
                                                    start,
                                                    end,
                                                    &tx,
                                                )
                                                .await?;
                                        }

                                        if let (_, Some(fixed)) = &parsed_range {
                                            let mut fixed_purl = purl.clone();
                                            fixed_purl.version = Some(fixed.clone());

                                            advisory_vuln
                                                .ingest_fixed_package_version(fixed_purl, &tx)
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

        Ok(())
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

    use test_log::test;
    use trustify_common::advisory::Assertion;

    use trustify_common::db::{Database, Transactional};
    use trustify_graph::graph::Graph;

    use crate::advisory::osv::loader::OsvLoader;

    #[test(tokio::test)]
    async fn loader() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingestors_osv_loader").await?;
        let graph = Graph::new(db);

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../etc/test-data/osv");

        let osv_json = test_data.join("RUSTSEC-2021-0079.json");
        let osv_file = File::open(osv_json)?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_none());

        let loaded_advisory = graph
            .get_advisory(
                "RUSTSEC-2021-0079",
                "RUSTSEC-2021-0079.json",
                "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51",
            )
            .await?;

        assert!(loaded_advisory.is_none());

        let loader = OsvLoader::new(&graph);

        loader.load("RUSTSEC-2021-0079.json", osv_file).await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2021-32714", Transactional::None)
            .await?;

        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory(
                "RUSTSEC-2021-0079",
                "RUSTSEC-2021-0079.json",
                "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51",
            )
            .await?;

        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        let affected_assertions = loaded_advisory.affected_assertions(()).await?;

        assert_eq!(1, affected_assertions.assertions.len());

        let affected_assertion = affected_assertions.assertions.get("pkg://cargo/hyper");
        assert!(affected_assertion.is_some());

        let affected_assertion = &affected_assertion.unwrap()[0];

        assert!(
            matches!( affected_assertion, Assertion::Affected {vulnerability,start_version,end_version}
                if start_version == "0.0.0-0"
                && end_version == "0.14.10"
                && vulnerability == "CVE-2021-32714"
            )
        );

        let fixed_assertions = loaded_advisory.fixed_assertions(()).await?;

        assert_eq!(1, fixed_assertions.assertions.len());

        let fixed_assertion = fixed_assertions.assertions.get("pkg://cargo/hyper");
        assert!(fixed_assertion.is_some());

        let fixed_assertion = fixed_assertion.unwrap();
        assert_eq!(1, fixed_assertion.len());

        let fixed_assertion = &fixed_assertion[0];

        assert!(
            matches!( fixed_assertion, Assertion::Fixed{vulnerability ,version }
                if version == "0.14.10"
                && vulnerability == "CVE-2021-32714"
            )
        );
        Ok(())
    }
}
