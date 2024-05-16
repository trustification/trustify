use crate::graph::{
    purl::creator::PurlCreator,
    sbom::{PackageCreator, PackageReference, SbomContext, SbomInformation},
};
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, db::Transactional, purl::Purl};
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
        let mut creator = PurlCreator::new();

        let mut packages = PackageCreator::new(
            self.sbom.sbom_id,
            sbom_data.package_information.len(),
            sbom_data.relationships.len(),
        );

        for package in &sbom_data.package_information {
            let mut refs = Vec::new();

            for r in &package.external_reference {
                match &*r.reference_type {
                    "purl" => {
                        if let Ok(purl) = Purl::from_str(&r.reference_locator) {
                            refs.push(PackageReference::Purl(purl.qualifier_uuid()));
                            creator.add(purl);
                        }
                    }
                    "cpe22Type" => {
                        if let Ok(cpe) = Cpe::from_str(&r.reference_locator) {
                            let cpe = self.graph.ingest_cpe22(cpe, &tx).await?;
                            refs.push(PackageReference::Cpe(cpe.cpe.id));
                        }
                    }
                    _ => {}
                }
            }

            packages.add(
                package.package_spdx_identifier.clone(),
                package.package_name.clone(),
                refs,
            );
        }

        let db = self.graph.connection(&tx);

        // create all purls

        creator.create(&db).await?;

        // create relationships

        for described in sbom_data.document_creation_information.document_describes {
            packages.relate(
                sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone(),
                Relationship::DescribedBy,
                described,
            );
        }

        for rel in &sbom_data.relationships {
            let Ok(SpdxRelationship(left, rel, right)) = rel.try_into() else {
                continue;
            };

            packages.relate(left.to_string(), rel, right.to_string());
        }

        // batch insert packages & relationships

        packages.create(&db).await?;

        // done

        Ok(())
    }
}

pub struct SpdxRelationship<'spdx>(pub &'spdx str, pub Relationship, pub &'spdx str);

impl<'spdx> TryFrom<(&'spdx str, &'spdx RelationshipType, &'spdx str)> for SpdxRelationship<'spdx> {
    type Error = ();

    fn try_from(
        (left, rel, right): (&'spdx str, &'spdx RelationshipType, &'spdx str),
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
        .map(|(left, rel, right)| Self(left, rel, right))
    }
}

impl<'spdx> TryFrom<&'spdx spdx_rs::models::Relationship> for SpdxRelationship<'spdx> {
    type Error = ();

    fn try_from(value: &'spdx spdx_rs::models::Relationship) -> Result<Self, Self::Error> {
        (
            value.spdx_element_id.as_str(),
            &value.relationship_type,
            value.related_spdx_element.as_str(),
        )
            .try_into()
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
pub fn parse_spdx(json: Value) -> Result<(SPDX, bool), serde_json::Error> {
    let (json, changed) = fix_license(json);
    Ok((serde_json::from_value(json)?, changed))
}
