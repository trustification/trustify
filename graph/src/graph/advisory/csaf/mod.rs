mod util;

use crate::db::Transactional;
use crate::graph::advisory::csaf::util::resolve_purls;
use crate::graph::advisory::AdvisoryContext;
use crate::graph::error::Error;
use csaf::{document::Category, Csaf};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, TransactionTrait};
use trustify_common::purl::Purl;
use trustify_entity as entity;

impl<'g> AdvisoryContext<'g> {
    pub async fn ingest_csaf(&self, csaf: Csaf) -> Result<(), Error> {
        let advisory = self.clone();

        // Ingest metadata
        let mut entity: entity::advisory::ActiveModel = self.advisory.clone().into();
        entity.title = Set(Some(csaf.document.title.clone().to_string()));
        entity
            .update(&self.graph.connection(Transactional::None))
            .await?;

        // Ingest vulnerabilities
        let txn = self.graph.db.begin().await?;

        for vuln in csaf.vulnerabilities.iter().flatten() {
            let id = match &vuln.cve {
                Some(cve) => cve,
                None => continue,
            };

            //let v = graph.ingest_vulnerability(id).await?;
            let advisory_vulnerability = advisory
                .ingest_vulnerability(id, Transactional::None)
                .await?;

            if let Some(ps) = &vuln.product_status {
                for r in ps.fixed.iter().flatten() {
                    for purl in resolve_purls(&csaf, r) {
                        let package = Purl::from(purl.clone());
                        let x = advisory_vulnerability
                            .ingest_fixed_package_version(package, Transactional::None)
                            .await?;
                    }
                }
                for r in ps.known_not_affected.iter().flatten() {
                    for purl in resolve_purls(&csaf, r) {
                        let package = Purl::from(purl.clone());
                        let x = advisory_vulnerability
                            .ingest_not_affected_package_version(package, Transactional::None)
                            .await?;
                    }
                }
                for r in ps.known_affected.iter().flatten() {
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
        txn.commit();
        Ok::<(), Error>(())
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::graph::Graph;
    use csaf::Csaf;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Instant;
    use test_log::test;

    #[test(tokio::test)]
    async fn advisory_csaf() -> Result<(), anyhow::Error> {
        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../etc/test-data");

        //let sbom = test_data.join( "openshift-4.13.json");
        let advisory = test_data.join("cve-2023-33201.json");

        let advisory = File::open(advisory)?;

        let start = Instant::now();
        let advisory_data: Csaf = serde_json::from_reader(advisory)?;

        let system = Graph::for_test("advisory_csaf").await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        advisory.ingest_csaf(advisory_data).await?;

        let assertions = advisory
            .vulnerability_assertions(Transactional::None)
            .await?;

        log::info!("{:#?}", assertions);

        Ok(())
    }
}
