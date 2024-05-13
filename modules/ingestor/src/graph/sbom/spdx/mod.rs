use crate::graph::package::creator::Creator;
use crate::graph::sbom::{SbomContext, SbomInformation};
use sea_orm::ActiveValue::Set;
use sea_orm::EntityTrait;
use sea_query::OnConflict;
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::io::Read;
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::cpe::Cpe;
use trustify_common::{
    db::{chunk::EntityChunkedIter, Transactional},
    purl::Purl,
};
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom_node, sbom_package,
    sbom_package_cpe_ref, sbom_package_purl_ref,
};

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

        let mut nodes = Vec::with_capacity(sbom_data.package_information.len());
        let mut packages = Vec::with_capacity(sbom_data.package_information.len());
        // assuming most packages will have a purl -> with_capacity
        let mut purl_refs = Vec::with_capacity(sbom_data.package_information.len());
        // assuming most packages will not have a CPE -> new
        let mut cpe_refs = Vec::new();

        for package in &sbom_data.package_information {
            nodes.push(sbom_node::ActiveModel {
                sbom_id: Set(self.sbom.sbom_id),
                node_id: Set(package.package_spdx_identifier.clone()),
                name: Set(package.package_name.clone()),
            });
            packages.push(sbom_package::ActiveModel {
                sbom_id: Set(self.sbom.sbom_id),
                node_id: Set(package.package_spdx_identifier.clone()),
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
                    "cpe22Type" => {
                        if let Ok(cpe) = Cpe::from_str(&r.reference_locator) {
                            let cpe = self.graph.ingest_cpe22(cpe, &tx).await?;
                            cpe_refs.push(sbom_package_cpe_ref::ActiveModel {
                                sbom_id: Set(self.sbom.sbom_id),
                                node_id: Set(package.package_spdx_identifier.clone()),
                                cpe_id: Set(cpe.cpe.id),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        let db = self.graph.connection(&tx);

        // create all purls

        creator.create(&self.graph.connection(&tx)).await?;

        // batch insert packages

        for batch in &nodes.into_iter().chunked() {
            sbom_node::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_node::Column::SbomId, sbom_node::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .do_nothing()
                .exec(&db)
                .await?;
        }

        for batch in &packages.into_iter().chunked() {
            sbom_package::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_package::Column::SbomId,
                        sbom_package::Column::NodeId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(&db)
                .await?;
        }

        for batch in &purl_refs.into_iter().chunked() {
            sbom_package_purl_ref::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_package_purl_ref::Column::SbomId,
                        sbom_package_purl_ref::Column::NodeId,
                        sbom_package_purl_ref::Column::QualifiedPackageId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(&db)
                .await?;
        }

        for batch in &cpe_refs.into_iter().chunked() {
            sbom_package_cpe_ref::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_package_cpe_ref::Column::SbomId,
                        sbom_package_cpe_ref::Column::NodeId,
                        sbom_package_cpe_ref::Column::CpeId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(&db)
                .await?;
        }

        let mut rels = Vec::with_capacity(sbom_data.relationships.len());

        for described in sbom_data.document_creation_information.document_describes {
            rels.push(package_relates_to_package::ActiveModel {
                sbom_id: Set(self.sbom.sbom_id),
                left_node_id: Set(sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone()),
                relationship: Set(Relationship::DescribedBy),
                right_node_id: Set(described),
            });
        }

        for rel in &sbom_data.relationships {
            let Ok(SpdxRelationship(left, rel, right)) = rel.try_into() else {
                continue;
            };

            rels.push(package_relates_to_package::ActiveModel {
                sbom_id: Set(self.sbom.sbom_id),
                left_node_id: Set(left.to_string()),
                relationship: Set(rel),
                right_node_id: Set(right.to_string()),
            });
        }

        for batch in &rels.into_iter().chunked() {
            package_relates_to_package::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        package_relates_to_package::Column::SbomId,
                        package_relates_to_package::Column::LeftNodeId,
                        package_relates_to_package::Column::Relationship,
                        package_relates_to_package::Column::RightNodeId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(&db)
                .await?;
        }

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
pub fn parse_spdx<R: Read>(data: R) -> Result<(SPDX, bool), serde_json::Error> {
    let json = serde_json::from_reader::<_, Value>(data)?;
    let (json, changed) = fix_license(json);
    Ok((serde_json::from_value(json)?, changed))
}
