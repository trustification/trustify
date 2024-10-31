use crate::{
    graph::{
        cpe::CpeCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
        sbom::{
            FileCreator, LicenseCreator, LicenseInfo, PackageCreator, PackageReference, References,
            RelationshipCreator, SbomContext, SbomInformation,
        },
    },
    service::Error,
};
use sbom_walker::report::{check, ReportSink};
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::{collections::HashMap, str::FromStr};
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
            data_licenses: vec![value.0.document_creation_information.data_license.clone()],
        }
    }
}

impl SbomContext {
    #[instrument(skip(tx, sbom_data, warnings), ret)]
    pub async fn ingest_spdx<TX: AsRef<Transactional>>(
        &self,
        sbom_data: SPDX,
        warnings: &dyn ReportSink,
        tx: TX,
    ) -> Result<(), Error> {
        // pre-flight checks

        check::spdx::all(warnings, &sbom_data);

        // prepare packages

        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();

        // prepare relationships

        let mut relationships =
            RelationshipCreator::with_capacity(self.sbom.sbom_id, sbom_data.relationships.len());

        let mut product_packages = vec![];

        for described in sbom_data.document_creation_information.document_describes {
            relationships.relate(
                described,
                Relationship::DescribedBy,
                sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone(),
            );
            product_packages.push(
                sbom_data
                    .document_creation_information
                    .spdx_identifier
                    .clone(),
            );
        }

        for rel in &sbom_data.relationships {
            let Ok(SpdxRelationship(left, rel, right)) = rel.try_into() else {
                continue;
            };

            relationships.relate(left.to_string(), rel, right.to_string());

            if rel == Relationship::DescribedBy {
                product_packages.push(left.to_string());
            }
        }

        let mut licenses = LicenseCreator::new();

        let license_refs = sbom_data
            .other_licensing_information_detected
            .iter()
            .map(|e| (e.license_identifier.clone(), e.license_name.clone()))
            .collect::<HashMap<_, _>>();

        let mut packages =
            PackageCreator::with_capacity(self.sbom.sbom_id, sbom_data.package_information.len());

        for package in &sbom_data.package_information {
            let declared_license_info = package.declared_license.as_ref().map(|e| LicenseInfo {
                license: e.to_string(),
                refs: license_refs.clone(),
            });

            let concluded_license_info = package.concluded_license.as_ref().map(|e| LicenseInfo {
                license: e.to_string(),
                refs: license_refs.clone(),
            });

            let mut refs = Vec::new();
            let mut license_refs = Vec::new();

            if let Some(declared_license) = declared_license_info {
                if declared_license.license != "NOASSERTION" {
                    licenses.add(&declared_license);
                    license_refs.push(declared_license);
                }
            }

            if let Some(concluded_license) = concluded_license_info {
                if concluded_license.license != "NOASSERTION" {
                    licenses.add(&concluded_license);
                    license_refs.push(concluded_license);
                }
            }

            let mut product_cpe = None;

            for r in &package.external_reference {
                match &*r.reference_type {
                    "purl" => match Purl::from_str(&r.reference_locator) {
                        Ok(purl) => {
                            refs.push(PackageReference::Purl {
                                versioned_purl: purl.version_uuid(),
                                qualified_purl: purl.qualifier_uuid(),
                            });
                            purls.add(purl);
                        }
                        Err(err) => {
                            log::info!("Failed to parse PURL ({}): {err}", r.reference_locator);
                        }
                    },
                    "cpe22Type" => match Cpe::from_str(&r.reference_locator) {
                        Ok(cpe) => {
                            refs.push(PackageReference::Cpe(cpe.uuid()));
                            cpes.add(cpe.clone());
                            // TODO: Product can have multiple CPE references
                            // possibly leading to multiple cpe keys.
                            // We need to investigate how to improve the design
                            // to support these use cases.
                            product_cpe = product_cpe.or(Some(cpe));
                        }
                        Err(err) => {
                            log::info!("Failed to parse CPE ({}): {err}", r.reference_locator);
                        }
                    },
                    _ => {}
                }
            }

            packages.add(
                package.package_spdx_identifier.clone(),
                package.package_name.clone(),
                package.package_version.clone(),
                refs,
                license_refs,
            );

            if product_packages.contains(&package.package_spdx_identifier) {
                let pr = self
                    .graph
                    .ingest_product(
                        package.package_name.clone(),
                        ProductInformation {
                            vendor: package.package_supplier.clone(),
                            cpe: product_cpe,
                        },
                        &tx,
                    )
                    .await?;

                if let Some(ver) = package.package_version.clone() {
                    pr.ingest_product_version(ver, Some(self.sbom.sbom_id), &tx)
                        .await?;
                }
            }
        }

        // prepare files

        let mut files =
            FileCreator::with_capacity(self.sbom.sbom_id, sbom_data.file_information.len());

        for file in sbom_data.file_information {
            files.add(file.file_spdx_identifier, file.file_name);
        }

        // get database connection

        let db = self.graph.connection(&tx);

        // create all purls and CPEs

        licenses.create(&db).await?;
        purls.create(&db).await?;
        cpes.create(&db).await?;

        // validate relationships before inserting

        let doc_id = [sbom_data
            .document_creation_information
            .spdx_identifier
            .as_str()];
        let sources = References::new()
            .add_source(&doc_id)
            .add_source(&packages)
            .add_source(&files);
        relationships.validate(sources).map_err(Error::Generic)?;

        // create packages, files, and relationships

        packages.create(&db).await?;
        files.create(&db).await?;
        relationships.create(&db).await?;

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
pub fn fix_license(report: &dyn ReportSink, mut json: Value) -> (Value, bool) {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str() {
                if let Err(err) = spdx_expression::SpdxExpression::parse(declared) {
                    package["licenseDeclared"] = "NOASSERTION".into();
                    changed = true;

                    let message =
                        format!("Replacing faulty SPDX license expression with NOASSERTION: {err}");
                    log::debug!("{message}");
                    report.error(message);
                }
            }
        }
    }

    (json, changed)
}

/// Parse a SPDX document, possibly replacing invalid license expressions.
///
/// Returns the parsed document and a flag indicating if license expressions got replaced.
pub fn parse_spdx(report: &dyn ReportSink, json: Value) -> Result<(SPDX, bool), serde_json::Error> {
    let (json, changed) = fix_license(report, json);
    Ok((serde_json::from_value(json)?, changed))
}
