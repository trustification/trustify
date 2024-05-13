use crate::graph::package::creator::Creator;
use crate::graph::sbom::{SbomContext, SbomInformation};
use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, EntityTrait};
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::collections::HashMap;
use std::io::Read;
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::{info_span, instrument};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_common::db::Transactional;
use trustify_common::purl::Purl;
use trustify_entity::relationship::Relationship;
use trustify_entity::{sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref};

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
            node_id: sbom.document_creation_information.spdx_identifier.clone(),
            name: sbom.document_creation_information.document_name.clone(),
            published,
            authors: value
                .0
                .document_creation_information
                .creation_info
                .creators
                .clone(),
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
        let mut creator = Creator::new();

        let mut packages = Vec::with_capacity(sbom_data.package_information.len());
        // assuming most packages will have a purl -> with_capacity
        let mut purl_refs = Vec::with_capacity(sbom_data.package_information.len());
        // assuming most packages will not have a CPE -> new
        let mut cpe_refs = Vec::<sbom_package_cpe_ref::ActiveModel>::new();

        for package in &sbom_data.package_information {
            packages.push(sbom_package::ActiveModel {
                sbom_id: Set(self.sbom.sbom_id),
                node_id: Set(package.package_spdx_identifier.clone()),
                name: Set(package.package_name.clone()),
            });

            for r in &package.external_reference {
                match &*r.reference_type {
                    "purl" => {
                        if let Ok(purl) = Purl::from_str(&r.reference_locator) {
                            purl_refs.push(sbom_package_purl_ref::ActiveModel {
                                sbom_id: Set(self.sbom.sbom_id),
                                node_id: Set(package.package_spdx_identifier.clone()),
                                qualified_package_id: Set(purl.qualifier_uuid()),
                            });
                            creator.add(purl);
                        }
                    }
                    // FIXME: add cpe22Type
                    _ => {}
                }
            }
        }

        // create all purls

        creator.create(&self.graph.connection(&tx)).await?;

        // batch insert packages

        for batch in &packages.into_iter().chunked() {
            sbom_package::Entity::insert_many(batch)
                .exec(&self.graph.connection(&tx))
                .await?;
        }

        for batch in &purl_refs.into_iter().chunked() {
            sbom_package_purl_ref::Entity::insert_many(batch)
                .exec(&self.graph.connection(&tx))
                .await?;
        }

        for batch in &cpe_refs.into_iter().chunked() {
            sbom_package_cpe_ref::Entity::insert_many(batch)
                .exec(&self.graph.connection(&tx))
                .await?;
        }

        // create a lookup cache for id[package information] -> package information
        let id_cache = info_span!("build id_cache").in_scope(|| {
            let mut cache = HashMap::with_capacity(sbom_data.package_information.len());

            for pi in &sbom_data.package_information {
                cache.insert(&pi.package_spdx_identifier, pi);
            }
            cache
        });

        // replace with: create A -[described by]-> B
        /*
        // For each thing described in the SBOM data, link it up to an sbom_cpe or sbom_package.
        for described in &sbom_data.document_creation_information.document_describes {
            let Some(described_package) = id_cache.get(described) else {
                continue;
            };

            for reference in &described_package.external_reference {
                match reference.reference_type.as_str() {
                    "purl" => {
                        self.ingest_describes_package(
                            &reference.reference_locator.as_str().try_into()?,
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
        */

        // create a lookup cache of id[package information] -> relatives
        let rel_cache = info_span!("build rel_cache").in_scope(|| {
            let mut rel_cache = HashMap::<_, Vec<_>>::new();

            for rel in &sbom_data.relationships {
                rel_cache.entry(&rel.spdx_element_id).or_default().push(rel);
            }
            rel_cache
        });

        // TODO: creator needs to be fed with purls, but rels need to use spdx-ids
        let mut rels = Vec::with_capacity(sbom_data.package_information.len());

        // connect all other tree-ish package trees in the context of this sbom.
        /*
        for package_info in &sbom_data.package_information {
            for package_ref in &package_info.external_reference {
                if package_ref.reference_type != "purl" {
                    continue;
                }

                let package_a = &package_ref.reference_locator;

                'rels: for relationship in rel_cache
                    .get(&package_info.package_spdx_identifier)
                    .into_iter()
                    .flatten()
                {
                    let Some(package) = id_cache.get(&relationship.related_spdx_element) else {
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

                        let left = left.try_into()?;
                        let right = right.try_into()?;

                        rels.push(self.create_relationship(&left, rel, &right));

                        creator.add(left);
                        creator.add(right);
                    }
                }
            }
        }

        log::info!("Relationships: {}", rels.len());
        */

        self.ingest_package_relates_to_package_many(&tx, rels)
            .await?;

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
            RelationshipType::Describes => Ok((right, Relationship::DescribedBy, left)),
            RelationshipType::DescribedBy => Ok((left, Relationship::DescribedBy, right)),
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
