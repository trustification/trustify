use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::sbom::SbomContext;
use huevos_entity::relationship::Relationship;
use sea_orm::TransactionTrait;
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::io::{Read, Seek};

impl SbomContext {
    pub async fn ingest_spdx_data<R: Read>(&self, sbom_data: R) -> Result<(), anyhow::Error> {
        let json = serde_json::from_reader::<_, Value>(sbom_data)?;

        let (json, _) = fix_license(json);

        let spdx_data: SPDX = serde_json::from_value(json)?;

        self.ingest_spdx(spdx_data).await?;

        Ok(())
    }

    pub async fn ingest_spdx(&self, sbom_data: SPDX) -> Result<(), anyhow::Error> {
        // FIXME: not sure this is correct. It may be that we need to use `DatabaseTransaction` instead of the `db` field
        let sbom = self.clone();
        //let system = self.system.clone();
        self.system
            .db
            .transaction(|tx| {
                Box::pin(async move {
                    let tx: Transactional = tx.into();
                    // For each thing described in the SBOM data, link it up to an sbom_cpe or sbom_package.
                    for described in &sbom_data.document_creation_information.document_describes {
                        for described_package in sbom_data
                            .package_information
                            .iter()
                            .filter(|each| each.package_spdx_identifier.eq(described))
                        {
                            for reference in &described_package.external_reference {
                                if reference.reference_type == "purl" {
                                    //println!("describes pkg {}", reference.reference_locator);
                                    sbom.ingest_describes_package(
                                        reference.reference_locator.clone(),
                                        tx,
                                    )
                                        .await?;
                                } else if reference.reference_type == "cpe22Type" {
                                    //println!("describes cpe22 {}", reference.reference_locator);
                                    if let Ok(cpe) = cpe::uri::Uri::parse(&reference.reference_locator) {
                                        sbom.ingest_describes_cpe22(
                                            cpe,
                                            tx,
                                        )
                                            .await?;

                                    }

                                }
                            }

                            // connect all other tree-ish package trees in the context of this sbom.
                            for package_info in &sbom_data.package_information {
                                let package_identifier = &package_info.package_spdx_identifier;
                                for package_ref in &package_info.external_reference {
                                    if package_ref.reference_type == "purl" {
                                        let package_a = package_ref.reference_locator.clone();
                                        //println!("pkg_a: {}", package_a);

                                        for relationship in sbom_data
                                            .relationships_for_spdx_id(package_identifier)
                                        {
                                            if let Some(package) = sbom_data
                                                .package_information
                                                .iter()
                                                .find(|each| {
                                                    each.package_spdx_identifier
                                                        == relationship.related_spdx_element
                                                })
                                            {
                                                for reference in &package.external_reference {
                                                    if reference.reference_type == "purl" {
                                                        let package_b = reference.reference_locator.clone();

                                                        // Check for the degenerate case that seems to appear where an SBOM inceptions itself.
                                                        if package_a != package_b {
                                                            if let Ok((left, rel, right)) = SpdxRelationship(
                                                                &package_a,
                                                                &relationship.relationship_type,
                                                                &package_b).try_into() {
                                                                sbom.ingest_package_relates_to_package(
                                                                    left,
                                                                    rel,
                                                                    right,
                                                                    tx,
                                                                ).await?
                                                            }
                                                        }
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

        Ok(())
    }
}

pub struct SpdxRelationship<'spdx>(&'spdx String, &'spdx RelationshipType, &'spdx String);

impl<'spdx> TryFrom<SpdxRelationship<'spdx>> for (&'spdx String, Relationship, &'spdx String) {
    type Error = ();

    fn try_from(
        SpdxRelationship(left, rel, right): SpdxRelationship<'spdx>,
    ) -> Result<Self, Self::Error> {
        match rel {
            RelationshipType::Contains => Ok((right, Relationship::ContainedBy, left)),
            RelationshipType::ContainedBy => Ok((left, Relationship::ContainedBy, right)),
            RelationshipType::DependsOn => Ok((right, Relationship::DependencyOf, left)),
            RelationshipType::DependencyOf => Ok((left, Relationship::DependencyOf, right)),
            RelationshipType::DevDependencyOf => Ok((left, Relationship::DevDependencyOf, right)),
            RelationshipType::OptionalDependencyOf => {
                Ok((left, Relationship::OptionalDependencyOf, right))
            }
            RelationshipType::ProvidedDependencyOf => {
                Ok((left, Relationship::ProvidedDependencyOf, right))
            }
            RelationshipType::TestDependencyOf => Ok((left, Relationship::TestDependencyOf, right)),
            RelationshipType::RuntimeDependencyOf => {
                Ok((left, Relationship::RuntimeDependencyOf, right))
            }
            RelationshipType::ExampleOf => Ok((left, Relationship::ExampleOf, right)),
            RelationshipType::Generates => Ok((right, Relationship::GeneratedFrom, left)),
            RelationshipType::GeneratedFrom => Ok((left, Relationship::GeneratedFrom, right)),
            RelationshipType::AncestorOf => Ok((left, Relationship::AncestorOf, right)),
            RelationshipType::DescendantOf => Ok((right, Relationship::AncestorOf, left)),
            RelationshipType::VariantOf => Ok((left, Relationship::VariantOf, right)),
            RelationshipType::BuildToolOf => Ok((left, Relationship::BuildToolOf, right)),
            RelationshipType::DevToolOf => Ok((left, Relationship::DevToolOf, right)),
            _ => Err(()),
        }
    }
}

fn fix_license(mut json: Value) -> (Value, bool) {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str() {
                if let Err(err) = spdx_expression::SpdxExpression::parse(declared) {
                    log::warn!("Replacing faulty SPDX license expression with NOASSERTION: {err}");
                    package["licenseDeclared"] = "NOASSERTION".into();
                    changed = true;
                }
            }
        }
    }

    (json, changed)
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;
    use huevos_entity::relationship::Relationship;
    use spdx_rs::models::SPDX;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Instant;

    #[tokio::test]
    async fn parse_spdx_quarkus() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("parse_spdx_quarkus").await?;

        let pwd = PathBuf::from_str(env!("PWD"))?;
        let test_data = pwd.join("test-data");

        // nope, has bad license expressions
        let sbom = test_data.join("quarkus-bom-2.13.8.Final-redhat-00004.json");

        let sbom_data = File::open(sbom)?;

        let start = Instant::now();
        let parse_time = start.elapsed();

        let start = Instant::now();
        let sbom = system
            .ingest_sbom("test.com/my-sbom.json", "10", Transactional::None)
            .await?;

        sbom.ingest_spdx_data(sbom_data).await?;
        let ingest_time = start.elapsed();
        let start = Instant::now();

        let described_cpe222 = sbom.describes_cpe22s(Transactional::None).await?;
        assert_eq!(1, described_cpe222.len());

        let described_packages = sbom.describes_packages(Transactional::None).await?;
        println!("{:#?}", described_packages);

        let contains = sbom
            .related_packages(
                Relationship::ContainedBy,
                described_packages[0].clone(),
                Transactional::None,
            )
            .await?;

        println!("{}", contains.len());

        assert!(contains.len() > 500);

        let query_time = start.elapsed();

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }

    // ignore because it's a slow slow slow test.
    #[ignore]
    #[tokio::test]
    async fn parse_spdx_openshift() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("parse_spdx_openshift").await?;

        let pwd = PathBuf::from_str(env!("PWD"))?;
        let test_data = pwd.join("test-data");

        // nope, has bad license expressions
        let sbom = test_data.join("openshift-4.13.json");

        let sbom_data = File::open(sbom)?;

        let start = Instant::now();
        let parse_time = start.elapsed();

        let start = Instant::now();
        let sbom = system
            .ingest_sbom("test.com/my-sbom.json", "10", Transactional::None)
            .await?;

        sbom.ingest_spdx_data(sbom_data).await?;
        let ingest_time = start.elapsed();
        let start = Instant::now();

        let described_cpe222 = sbom.describes_cpe22s(Transactional::None).await?;
        assert_eq!(1, described_cpe222.len());

        let described_packages = sbom.describes_packages(Transactional::None).await?;
        println!("{:#?}", described_packages);

        let contains = sbom
            .related_packages(
                Relationship::ContainedBy,
                described_packages[0].clone(),
                Transactional::None,
            )
            .await?;

        println!("{}", contains.len());

        assert!(contains.len() > 500);

        let query_time = start.elapsed();

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }

    #[tokio::test]
    async fn parse_spdx() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("parse_spdx").await?;

        let pwd = PathBuf::from_str(env!("PWD"))?;
        let test_data = pwd.join("test-data");

        //let sbom = test_data.join( "openshift-4.13.json");
        let sbom = test_data.join("ubi9-9.2-755.1697625012.json");

        let sbom = File::open(sbom)?;

        let start = Instant::now();
        let sbom_data: SPDX = serde_json::from_reader(sbom)?;
        let parse_time = start.elapsed();

        let start = Instant::now();
        let sbom = system
            .ingest_sbom("test.com/my-sbom.json", "10", Transactional::None)
            .await?;

        sbom.ingest_spdx(sbom_data).await?;
        let ingest_time = start.elapsed();
        let start = Instant::now();

        let described = sbom.describes_packages(Transactional::None).await?;

        assert_eq!(1, described.len());

        let contains = sbom
            .related_packages(
                Relationship::ContainedBy,
                described[0].clone(),
                Transactional::None,
            )
            .await?;

        println!("{}", contains.len());

        assert!(contains.len() > 500);

        let query_time = start.elapsed();

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }
}
