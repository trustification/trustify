use crate::service::advisory::csaf::util::resolve_purls;
use crate::service::hashing::HashingRead;
use crate::service::Error;
use csaf::Csaf;
use std::io::Read;
use trustify_common::purl::Purl;
use trustify_module_graph::graph::Graph;

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
    ) -> Result<String, Error> {
        let mut reader = HashingRead::new(document);

        let csaf: Csaf = serde_json::from_reader(&mut reader)?;

        let tx = self.graph.transaction().await?;

        let hashes = reader.hashes();
        let sha256 = hex::encode(hashes.sha256.as_ref());

        let advisory_id = csaf.document.tracking.id.clone();

        let advisory = self
            .graph
            .ingest_advisory(&advisory_id, location, sha256, &tx)
            .await?;

        for (cve_id, vuln) in csaf.vulnerabilities.iter().flatten().filter_map(|vuln| {
            vuln.cve.as_ref().map(|cve_id| {
                // produce a tuple containing a CVE ID and the original vuln,
                // as all subsequent work is only relevant if the CVE ID is
                // not None.
                (cve_id.clone(), vuln)
            })
        }) {
            let advisory_vulnerability = advisory.link_to_vulnerability(&cve_id, &tx).await?;

            // can't use vuln.product_status.and_then(...)
            // due to lack of support for async closure Fns.
            if let Some(ps) = &vuln.product_status {
                for r in ps.fixed.iter().flatten() {
                    for purl in resolve_purls(&csaf, r) {
                        let package = Purl::from(purl.clone());
                        advisory_vulnerability
                            .ingest_fixed_package_version(package, &tx)
                            .await?;
                    }
                }
                for r in ps.known_not_affected.iter().flatten() {
                    for purl in resolve_purls(&csaf, r) {
                        let package = Purl::from(purl.clone());
                        advisory_vulnerability
                            .ingest_not_affected_package_version(package, &tx)
                            .await?;
                    }
                }
                for _r in ps.known_affected.iter().flatten() {
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
            }
        }
        tx.commit().await?;
        Ok(advisory_id)
    }
}
