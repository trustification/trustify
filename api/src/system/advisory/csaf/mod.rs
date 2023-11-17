mod util;

use csaf::{Csaf, document::Category};
use sea_orm::TransactionTrait;
use huevos_common::purl::Purl;
use crate::db::Transactional;
use crate::system::advisory::AdvisoryContext;
use crate::system::advisory::csaf::util::resolve_purls;
use crate::system::error::Error;

impl AdvisoryContext {
    pub async fn ingest_csaf(&self, csaf: Csaf, tx: Transactional<'_>) -> Result<(), anyhow::Error> {
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
                        advisory.ingest_vulnerability(id, Transactional::None).await?;

                        if let Some(ps) = &vuln.product_status {
                            for r in ps.fixed.iter().flatten() {
                                for purl in resolve_purls(&csaf, r) {
                                    let package = Purl::from(purl.clone());
                                    //system
                                    //.ingest_vulnerability_fixed(package, &v, "vex")
                                    //.await?
                                    advisory
                                        .ingest_fixed_package_version(package, Transactional::None)
                                        .await?;
                                }
                            }
                        }
                    }
                    Ok::<(), Error>(())
                })
            }).await?;
        Ok(())
    }
}