use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::sbom::SbomContext;
use huevos_entity::relationship::Relationship;
use sea_orm::TransactionTrait;
use spdx_rs::models::{RelationshipType, SPDX};

impl SbomContext {
    async fn ingest_spdx(&self, sbom_data: SPDX) -> Result<(), anyhow::Error> {
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
                        if let Some(described_package) = sbom_data
                            .package_information
                            .iter()
                            .find(|each| each.package_spdx_identifier.eq(described))
                        {
                            for reference in &described_package.external_reference {
                                if reference.reference_type == "purl" {
                                    sbom.ingest_describes_package(
                                        reference.reference_locator.clone(),
                                        tx,
                                    )
                                        .await?;
                                } else if reference.reference_type == "cpe22Type" {
                                    sbom.ingest_describes_cpe(
                                        &reference.reference_locator,
                                        tx,
                                    )
                                        .await?;
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
                                                        //println!("pkg_b: {}", package_b);

                                                        match relationship.relationship_type {
                                                            RelationshipType::Describes => {}
                                                            RelationshipType::DescribedBy => {}
                                                            RelationshipType::Contains => {
                                                                sbom.ingest_package_relates_to_package(
                                                                    package_b.clone(),
                                                                    Relationship::ContainedBy,
                                                                    package_a.clone(),
                                                                    tx
                                                                ).await?
                                                            }
                                                            RelationshipType::ContainedBy => {
                                                                sbom.ingest_package_relates_to_package(
                                                                    package_a.clone(),
                                                                    Relationship::ContainedBy,
                                                                    package_b,
                                                                    tx
                                                                ).await?
                                                            }
                                                            RelationshipType::DependsOn => {}
                                                            RelationshipType::DependencyOf => {}
                                                            RelationshipType::DependencyManifestOf => {}
                                                            RelationshipType::BuildDependencyOf => {}
                                                            RelationshipType::DevDependencyOf => {}
                                                            RelationshipType::OptionalDependencyOf => {}
                                                            RelationshipType::ProvidedDependencyOf => {}
                                                            RelationshipType::TestDependencyOf => {}
                                                            RelationshipType::RuntimeDependencyOf => {}
                                                            RelationshipType::ExampleOf => {}
                                                            RelationshipType::Generates => {}
                                                            RelationshipType::GeneratedFrom => {}
                                                            RelationshipType::AncestorOf => {}
                                                            RelationshipType::DescendantOf => {}
                                                            RelationshipType::VariantOf => {}
                                                            RelationshipType::DistributionArtifact => {}
                                                            RelationshipType::PatchFor => {}
                                                            RelationshipType::PatchApplied => {}
                                                            RelationshipType::CopyOf => {}
                                                            RelationshipType::FileAdded => {}
                                                            RelationshipType::FileDeleted => {}
                                                            RelationshipType::FileModified => {}
                                                            RelationshipType::ExpandedFromArchive => {}
                                                            RelationshipType::DynamicLink => {}
                                                            RelationshipType::StaticLink => {}
                                                            RelationshipType::DataFileOf => {}
                                                            RelationshipType::TestCaseOf => {}
                                                            RelationshipType::BuildToolOf => {}
                                                            RelationshipType::DevToolOf => {}
                                                            RelationshipType::TestOf => {}
                                                            RelationshipType::TestToolOf => {}
                                                            RelationshipType::DocumentationOf => {}
                                                            RelationshipType::OptionalComponentOf => {}
                                                            RelationshipType::MetafileOf => {}
                                                            RelationshipType::PackageOf => {}
                                                            RelationshipType::Amends => {}
                                                            RelationshipType::PrerequisiteFor => {}
                                                            RelationshipType::HasPrerequisite => {}
                                                            RelationshipType::RequirementDescriptionFor => {}
                                                            RelationshipType::SpecificationFor => {}
                                                            RelationshipType::Other => {}
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
    use crate::db::Transactional;
    use crate::system::InnerSystem;
    use huevos_entity::relationship::Relationship;
    use spdx_rs::models::SPDX;
    use std::fs::File;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Instant;

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

        assert!(contains.len() > 600);

        let query_time = start.elapsed();

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }
}
