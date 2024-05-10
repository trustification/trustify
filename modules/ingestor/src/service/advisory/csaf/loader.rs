use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::graph::advisory::{AdvisoryContext, AdvisoryInformation};
use crate::graph::Graph;
use crate::service::advisory::csaf::util::resolve_purls;
use crate::service::hashing::HashingRead;
use crate::service::Error;
use csaf::vulnerability::{ProductStatus, Vulnerability};
use csaf::Csaf;
use std::io::Read;
use time::OffsetDateTime;
use trustify_common::db::Transactional;
use trustify_common::purl::Purl;

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
        checksum: &str,
    ) -> Result<String, Error> {
        let mut reader = HashingRead::new(document);

        let csaf: Csaf = serde_json::from_reader(&mut reader)?;

        let tx = self.graph.transaction().await?;

        let digests = reader.finish().map_err(|e| Error::Generic(e.into()))?;
        let encoded_sha256 = hex::encode(digests.sha256);
        if checksum != encoded_sha256 {
            return Err(Error::Storage(anyhow::Error::msg(
                "document integrity check failed",
            )));
        }

        let advisory_id = csaf.document.tracking.id.clone();

        let advisory = self
            .graph
            .ingest_advisory(
                &advisory_id,
                location,
                encoded_sha256,
                Information(&csaf),
                &tx,
            )
            .await?;

        for vuln in csaf.vulnerabilities.iter().flatten() {
            self.ingest_vulnerability(&csaf, &advisory, vuln, &tx)
                .await?;
        }

        tx.commit().await?;
        Ok(advisory_id)
    }

    async fn ingest_vulnerability<TX: AsRef<Transactional>>(
        &self,
        csaf: &Csaf,
        advisory: &AdvisoryContext<'_>,
        vulnerability: &Vulnerability,
        tx: TX,
    ) -> Result<(), Error> {
        if let Some(cve_id) = &vulnerability.cve {
            let advisory_vulnerability = advisory.link_to_vulnerability(cve_id, &tx).await?;

            if let Some(product_status) = &vulnerability.product_status {
                self.ingest_product_statuses(csaf, &advisory_vulnerability, product_status, &tx)
                    .await?;
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
