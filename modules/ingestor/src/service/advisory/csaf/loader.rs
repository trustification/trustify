use crate::model::IngestResult;
use crate::{
    graph::{
        advisory::{
            advisory_vulnerability::AdvisoryVulnerabilityContext, AdvisoryContext,
            AdvisoryInformation, AdvisoryVulnerabilityInformation,
        },
        Graph,
    },
    service::{advisory::csaf::util::resolve_purls, Error},
};
use csaf::{
    vulnerability::{ProductStatus, Vulnerability},
    Csaf,
};
use std::io::Read;
use std::str::FromStr;
use time::OffsetDateTime;
use trustify_common::{db::Transactional, hashing::Digests, id::Id, purl::Purl};
use trustify_cvss::cvss3::Cvss3Base;

struct Information<'a>(&'a Csaf);

impl<'a> From<Information<'a>> for AdvisoryInformation {
    fn from(value: Information<'a>) -> Self {
        let value = value.0;
        Self {
            title: Some(value.document.title.clone()),
            issuer: Some(value.document.publisher.name.clone()),
            published: OffsetDateTime::from_unix_timestamp(
                value.document.tracking.initial_release_date.timestamp(),
            )
            .ok(),
            modified: OffsetDateTime::from_unix_timestamp(
                value.document.tracking.current_release_date.timestamp(),
            )
            .ok(),
            withdrawn: None,
        }
    }
}

pub struct CsafLoader<'g> {
    graph: &'g Graph,
}

impl<'g> CsafLoader<'g> {
    pub fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    pub async fn load<L: Into<String>, R: Read>(
        &self,
        location: L,
        document: R,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let csaf: Csaf = serde_json::from_reader(document)?;

        let tx = self.graph.transaction().await?;

        let advisory_id = csaf.document.tracking.id.clone();

        let advisory = self
            .graph
            .ingest_advisory(&advisory_id, location, digests, Information(&csaf), &tx)
            .await?;

        for vuln in csaf.vulnerabilities.iter().flatten() {
            self.ingest_vulnerability(&csaf, &advisory, vuln, &tx)
                .await?;
        }

        tx.commit().await?;

        Ok(IngestResult {
            id: Id::Uuid(advisory.advisory.id),
            document_id: advisory_id,
        })
    }

    async fn ingest_vulnerability<TX: AsRef<Transactional>>(
        &self,
        csaf: &Csaf,
        advisory: &AdvisoryContext<'_>,
        vulnerability: &Vulnerability,
        tx: TX,
    ) -> Result<(), Error> {
        if let Some(cve_id) = &vulnerability.cve {
            let advisory_vulnerability = advisory
                .link_to_vulnerability(
                    cve_id,
                    Some(AdvisoryVulnerabilityInformation {
                        title: vulnerability.title.clone(),
                        summary: None,
                        description: None,
                        discovery_date: vulnerability.discovery_date.and_then(|date| {
                            OffsetDateTime::from_unix_timestamp(date.timestamp()).ok()
                        }),
                        release_date: vulnerability.release_date.and_then(|date| {
                            OffsetDateTime::from_unix_timestamp(date.timestamp()).ok()
                        }),
                    }),
                    &tx,
                )
                .await?;

            log::debug!("{advisory_vulnerability:?}");

            if let Some(product_status) = &vulnerability.product_status {
                self.ingest_product_statuses(csaf, &advisory_vulnerability, product_status, &tx)
                    .await?;
            }

            if let Some(scores) = &vulnerability.scores {
                for score in scores {
                    if let Some(v3) = &score.cvss_v3 {
                        match Cvss3Base::from_str(&v3.to_string()) {
                            Ok(cvss3) => {
                                log::debug!("{cvss3:?}");
                                advisory_vulnerability
                                    .ingest_cvss3_score(cvss3, &tx)
                                    .await?;
                            }
                            Err(err) => {
                                log::warn!("Unable to parse CVSS3: {:#?}", err);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn ingest_product_statuses<TX: AsRef<Transactional>>(
        &self,
        csaf: &Csaf,
        advisory_vulnerability: &AdvisoryVulnerabilityContext<'_>,
        product_status: &ProductStatus,
        tx: TX,
    ) -> Result<(), Error> {
        for r in product_status.fixed.iter().flatten() {
            for purl in resolve_purls(csaf, r) {
                let package = Purl::from(purl.clone());
                advisory_vulnerability
                    .ingest_fixed_package_version(&package, &tx)
                    .await?;
            }
        }
        for r in product_status.known_not_affected.iter().flatten() {
            for purl in resolve_purls(csaf, r) {
                let package = Purl::from(purl.clone());
                advisory_vulnerability
                    .ingest_not_affected_package_version(&package, &tx)
                    .await?;
            }
        }
        for _r in product_status.known_affected.iter().flatten() {
            /*
            for purl in resolve_purls(&csaf, r) {
                let package = Purl::from(purl.clone());
                log::debug!("{}", package.to_string());
                //advisory_vulnerability
                    //.ingest_affected_package_range(package, Transactional::None)
                    //.await?;
            }

             */
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::ToHex;

    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    // use trustify_common::advisory::Assertion;
    use trustify_common::db::{test::TrustifyContext, Transactional};

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn loader(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);

        let data = include_bytes!("../../../../../../etc/test-data/csaf/CVE-2023-20862.json");
        let digests = Digests::digest(data);

        let loader = CsafLoader::new(&graph);
        loader
            .load("CVE-2023-20862.json", &data[..], &digests)
            .await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2023-20862", Transactional::None)
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
        // let loaded_advisory_vulnerability = &loaded_advisory_vulnerabilities[0];

        // let affected_assertions = loaded_advisory_vulnerability
        //     .affected_assertions(())
        //     .await?;
        // assert_eq!(1, affected_assertions.assertions.len());

        // let affected_assertion = affected_assertions.assertions.get("pkg://cargo/hyper");
        // assert!(affected_assertion.is_some());

        // let affected_assertion = &affected_assertion.unwrap()[0];
        // assert!(
        //     matches!( affected_assertion, Assertion::Affected {start_version,end_version}
        //         if start_version == "0.0.0-0"
        //         && end_version == "0.14.10"
        //     )
        // );

        // let fixed_assertions = loaded_advisory_vulnerability.fixed_assertions(()).await?;
        // assert_eq!(1, fixed_assertions.assertions.len());

        // let fixed_assertion = fixed_assertions.assertions.get("pkg://cargo/hyper");
        // assert!(fixed_assertion.is_some());

        // let fixed_assertion = fixed_assertion.unwrap();
        // assert_eq!(1, fixed_assertion.len());

        // let fixed_assertion = &fixed_assertion[0];
        // assert!(matches!( fixed_assertion, Assertion::Fixed{version }
        //     if version == "0.14.10"
        // ));

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2023-20862", ())
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(()).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn multiple_vulnerabilities(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db);
        let loader = CsafLoader::new(&graph);

        let data = include_bytes!("../../../../../../etc/test-data/csaf/rhsa-2024_3666.json");
        let digests = Digests::digest(data);

        loader.load("test", &data[..], &digests).await?;

        let loaded_vulnerability = graph
            .get_vulnerability("CVE-2024-23672", Transactional::None)
            .await?;
        assert!(loaded_vulnerability.is_some());

        let loaded_advisory = graph
            .get_advisory_by_digest(&digests.sha256.encode_hex::<String>(), Transactional::None)
            .await?;
        assert!(loaded_advisory.is_some());

        let loaded_advisory = loaded_advisory.unwrap();

        assert!(loaded_advisory.advisory.issuer_id.is_some());

        let loaded_advisory_vulnerabilities = loaded_advisory.vulnerabilities(()).await?;
        assert_eq!(2, loaded_advisory_vulnerabilities.len());

        let advisory_vuln = loaded_advisory
            .get_vulnerability("CVE-2024-23672", ())
            .await?;
        assert!(advisory_vuln.is_some());

        let advisory_vuln = advisory_vuln.unwrap();
        let scores = advisory_vuln.cvss3_scores(()).await?;
        assert_eq!(1, scores.len());

        let score = scores[0];
        assert_eq!(
            score.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
        );

        Ok(())
    }
}
