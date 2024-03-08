mod util;

use crate::db::Transactional;
use crate::system::advisory::csaf::util::resolve_purls;
use crate::system::advisory::AdvisoryContext;
use crate::system::error::Error;
use csaf::{document::Category, Csaf};
use sea_orm::TransactionTrait;
use trustify_common::purl::Purl;

impl AdvisoryContext {
    pub async fn ingest_csaf(&self, csaf: Csaf) -> Result<(), anyhow::Error> {
        let advisory = self.clone();
        //let system = self.system.clone();
        self.system
            .db
            .transaction(|tx| {
                Box::pin(async move {
                    for vuln in csaf.vulnerabilities.iter().flatten() {
                        let id = match &vuln.cve {
                            Some(cve) => cve,
                            None => continue,
                        };

                        //let v = system.ingest_vulnerability(id).await?;
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
                                        .ingest_not_affected_package_version(
                                            package,
                                            Transactional::None,
                                        )
                                        .await?;
                                }
                            }
                            for r in ps.known_affected.iter().flatten() {
                                /*
                                for purl in resolve_purls(&csaf, r) {
                                    let package = Purl::from(purl.clone());
                                    println!("{}", package.to_string());
                                    //advisory_vulnerability
                                        //.ingest_affected_package_range(package, Transactional::None)
                                        //.await?;
                                }

                                 */
                            }
                        }
                    }
                    Ok::<(), Error>(())
                })
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;
    use csaf::Csaf;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Instant;

    #[tokio::test]
    async fn advisory_csaf() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../test-data");

        //let sbom = test_data.join( "openshift-4.13.json");
        let advisory = test_data.join("cve-2023-33201.json");

        let advisory = File::open(advisory)?;

        let start = Instant::now();
        let advisory_data: Csaf = serde_json::from_reader(advisory)?;

        let (db, system) = InnerSystem::for_test("advisory_csaf").await?;

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

        println!("{:#?}", assertions);

        Ok(())
    }
}
