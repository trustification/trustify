use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;

use crate::Purl;
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use spdx_rs::models::{RelationshipType, SPDX};
use crate::system::System;

use super::error::Error;

pub struct SbomSystem {
    pub(crate) db: Arc<DatabaseConnection>,
}

impl System {

    pub async fn ingest_sbom(&self, sbom: SPDX) -> Result<(), anyhow::Error> {

        // FIXME: not sure this is correct. It may be that we need to use `DatabaseTransaction` instead of the `db` field
        let system = self.clone();
        self.db
            .transaction(|tx| {
                Box::pin(async move {
                    for described in &sbom.document_creation_information.document_describes {
                        println!("described: {}", described);

                        if let Some(described_package) = sbom
                            .package_information
                            .iter()
                            .find(|each| each.package_spdx_identifier.eq(described))
                        {
                            for described_reference in &described_package.external_reference {
                                if described_reference.reference_type == "purl" {
                                    let described_purl =
                                        Purl::from(&*described_reference.reference_locator);
                                    for relationship in
                                        &sbom.relationships_for_related_spdx_id(&described)
                                    {
                                        if relationship.relationship_type
                                            == RelationshipType::ContainedBy
                                        {
                                            if let Some(package) =
                                                sbom.package_information.iter().find(|each| {
                                                    each.package_spdx_identifier
                                                        == relationship.spdx_element_id
                                                })
                                            {
                                                //println!("{:#?}", package.external_reference);
                                                for reference in &package.external_reference {
                                                    if reference.reference_type == "purl" {
                                                        system
                                                            .ingest_package(
                                                                &*reference.reference_locator,
                                                            )
                                                            .await?;

                                                        system
                                                            .ingest_package_dependency(
                                                                described_purl.clone(),
                                                                &*reference.reference_locator,
                                                            )
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

                    Ok::<(), Error>(())
                })
            })
            .await?;

        /*
        println!("DESCRIBES {:?}", describes);

        println!("--------packages--");
        for pkg in &sbom.package_information {
            for reference in &pkg.external_reference {
                if reference.reference_type == "purl" {
                    println!("{:#?}", reference.reference_locator);
                    package_system.ingest_package(
                        &*reference.reference_locator
                    ).await?;
                }
            }
        }

         */

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::TransactionTrait;
    use spdx_rs::models::SPDX;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Instant;

    use crate::system::System;

    #[tokio::test]
    async fn parse_spdx() -> Result<(), anyhow::Error> {
        let system = System::start().await?;
        system.bootstrap().await?;

        let pwd = PathBuf::from_str(env!("PWD"))?;
        let test_data = pwd.join("test-data");

        //let sbom = test_data.join( "openshift-4.13.json");
        let sbom = test_data.join("ubi9-9.2-755.1697625012.json");

        let sbom = File::open(sbom)?;

        let start = Instant::now();
        let sbom: SPDX = serde_json::from_reader(sbom)?;
        let parse_time = start.elapsed();

        let start = Instant::now();
        system.ingest_sbom(sbom).await?;
        let ingest_time = start.elapsed();
        let start = Instant::now();

        //for pkg in system.package().packages().await? {
        //println!("{}", pkg);
        //}

        /*
        let deps = package_system.transitive_dependencies(
            "pkg:oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012"
        ).await?;
         */

        let deps = system.direct_dependencies(
            "pkg:oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012"
        ).await?;
        let query_time = start.elapsed();

        println!("{:#?}", deps);

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }
}
