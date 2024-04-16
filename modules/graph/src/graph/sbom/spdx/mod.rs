mod tests;

use crate::graph::error::Error;
use crate::graph::sbom::{PackageCache, SbomContext, SbomInformation};
use sea_orm::TransactionTrait;
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::collections::HashMap;
use std::io::Read;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::db::Transactional;
use trustify_entity::relationship::Relationship;

pub struct Information<'a>(pub &'a SPDX);

impl<'a> From<Information<'a>> for SbomInformation {
    fn from(value: Information<'a>) -> Self {
        let sbom = value.0;

        let published = OffsetDateTime::from_unix_timestamp(
            sbom.document_creation_information
                .creation_info
                .created
                .timestamp(),
        )
        .ok();

        Self {
            title: Some(sbom.document_creation_information.document_name.clone()),
            published,
        }
    }
}

impl SbomContext {
    #[instrument(skip(tx, sbom_data), err)]
    pub async fn ingest_spdx<TX: AsRef<Transactional>>(
        &self,
        sbom_data: SPDX,
        tx: TX,
    ) -> Result<(), anyhow::Error> {
        // create a lookup cache for id -> package information
        let mut cache = HashMap::with_capacity(sbom_data.package_information.len());

        for pi in &sbom_data.package_information {
            cache.insert(&pi.package_spdx_identifier, pi);
        }

        // For each thing described in the SBOM data, link it up to an sbom_cpe or sbom_package.
        for described in &sbom_data.document_creation_information.document_describes {
            let Some(described_package) = cache.get(described) else {
                continue;
            };

            for reference in &described_package.external_reference {
                match reference.reference_type.as_str() {
                    "purl" => {
                        self.ingest_describes_package(
                            reference.reference_locator.as_str().try_into()?,
                            &tx,
                        )
                        .await?;
                    }
                    "cpe22Type" => {
                        if let Ok(cpe) = cpe::uri::Uri::parse(&reference.reference_locator) {
                            self.ingest_describes_cpe22(cpe, &tx).await?;
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut lookup_cache = PackageCache::new(
            sbom_data.package_information.len(),
            &self.graph,
            tx.as_ref(),
        );

        // connect all other tree-ish package trees in the context of this sbom.
        for package_info in &sbom_data.package_information {
            for package_ref in &package_info.external_reference {
                if package_ref.reference_type != "purl" {
                    continue;
                }

                let package_a = &package_ref.reference_locator;
                //log::debug!("pkg_a: {}", package_a);

                'rels: for relationship in
                    sbom_data.relationships_for_spdx_id(&package_info.package_spdx_identifier)
                {
                    let Some(package) = cache.get(&relationship.related_spdx_element) else {
                        continue 'rels;
                    };

                    'refs: for reference in &package.external_reference {
                        if reference.reference_type != "purl" {
                            continue 'refs;
                        }

                        let package_b = &reference.reference_locator;

                        // Check for the degenerate case that seems to appear where an SBOM inceptions itself.
                        if package_a == package_b {
                            continue 'refs;
                        }

                        // check if we have a valid relationship
                        let Ok((left, rel, right)) =
                            SpdxRelationship(package_a, &relationship.relationship_type, package_b)
                                .try_into()
                        else {
                            continue 'refs;
                        };

                        // now add it
                        self.ingest_package_relates_to_package(
                            &mut lookup_cache,
                            left.try_into()?,
                            rel,
                            right.try_into()?,
                            &tx,
                        )
                        .await?
                    }
                }
            }
        }

        log::info!("Package cache: {lookup_cache:?}");

        Ok(())
    }
}

pub struct SpdxRelationship<'spdx>(&'spdx str, &'spdx RelationshipType, &'spdx str);

impl<'spdx> TryFrom<SpdxRelationship<'spdx>> for (&'spdx str, Relationship, &'spdx str) {
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

/// Check the document for invalid SPDX license expressions and replace them with `NOASSERTION`.
pub fn fix_license(mut json: Value) -> (Value, bool) {
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

/// Parse a SPDX document, possibly replacing invalid license expressions.
///
/// Returns the parsed document and a flag indicating if license expressions got replaced.
pub fn parse_spdx<R: Read>(data: R) -> Result<(SPDX, bool), serde_json::Error> {
    let json = serde_json::from_reader::<_, Value>(data)?;
    let (json, changed) = fix_license(json);
    Ok((serde_json::from_value(json)?, changed))
}
