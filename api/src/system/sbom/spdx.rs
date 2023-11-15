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
        let system = self.system.clone();
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

                                        for relationship in sbom_data
                                            .relationships_for_related_spdx_id(package_identifier)
                                        {
                                            if let Some(package) = sbom_data
                                                .package_information
                                                .iter()
                                                .find(|each| {
                                                    each.package_spdx_identifier
                                                        == relationship.spdx_element_id
                                                })
                                            {
                                                for reference in &package.external_reference {
                                                    if reference.reference_type == "purl" {
                                                        let package_b = reference.reference_locator.clone();

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
