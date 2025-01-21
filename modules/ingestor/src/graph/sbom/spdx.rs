use crate::graph::sbom::{ExtractedLicensingInfoCreator, ExtratedLicensingInfo};
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
use sea_orm::ConnectionTrait;
use serde_json::Value;
use spdx_rs::models::{RelationshipType, SPDX};
use std::{collections::HashMap, str::FromStr};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::license::LicenseCategory;
use trustify_entity::relationship::Relationship;
use uuid::Uuid;

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
    #[instrument(skip(db, sbom_data, warnings), ret)]
    pub async fn ingest_spdx<C: ConnectionTrait>(
        &self,
        sbom_data: SPDX,
        warnings: &dyn ReportSink,
        db: &C,
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

        let mut license_refs = ExtractedLicensingInfoCreator::new();
        let mut extracted_licensing_info_list = Vec::new();

        for license_ref in sbom_data.other_licensing_information_detected {
            let extracted_licensing_info = &ExtratedLicensingInfo::with_sbom_id(
                self.sbom.sbom_id,
                license_ref.license_identifier.clone(),
                license_ref.license_name,
                license_ref.extracted_text,
                license_ref.license_comment,
            );
            license_refs.add(extracted_licensing_info);

            extracted_licensing_info_list.push(extracted_licensing_info.clone());
        }

        let mut licenses = LicenseCreator::new_with_extracted_licensing_info_and_sbom_id(
            extracted_licensing_info_list.clone(),
            self.sbom.sbom_id.clone(),
        );

        let mut packages =
            PackageCreator::with_capacity(self.sbom.sbom_id, sbom_data.package_information.len());

        fn get_license_ref_id_from_extracted_licensing_info(
            license_id: String,
            sbom_id: Uuid,
            extracted_licensing_info_list: Vec<ExtratedLicensingInfo>,
        ) -> Option<Uuid> {
            let license_ref_data = extracted_licensing_info_list
                .iter()
                .find(|e| e.license_id == license_id && e.sbom_id == sbom_id);
            if let Some(data) = license_ref_data {
                Some(data.id)
            } else {
                None
            }
        }

        for package in &sbom_data.package_information {
            if let Some(declared_license) = &package.declared_license {
                for (license) in declared_license.licenses() {
                    if license.license_ref.clone() {
                        let license_ref_id = get_license_ref_id_from_extracted_licensing_info(
                            format!("LicenseRef-{}", license.identifier.clone().to_string()),
                            self.sbom.sbom_id.clone(),
                            extracted_licensing_info_list.clone(),
                        );
                        licenses.add(&LicenseInfo {
                            license: format!("LicenseRef-{}", license.identifier.to_string()),
                            license_category: LicenseCategory::SPDXDECLARED,
                            license_name: license.identifier.clone().to_string(),
                            license_ref_id,
                            is_license_ref: license.license_ref,
                        });
                    } else {
                        licenses.add(&LicenseInfo {
                            license: license.identifier.to_string(),
                            license_category: LicenseCategory::SPDXDECLARED,
                            license_name: license.identifier.clone().to_string(),
                            license_ref_id: None,
                            is_license_ref: license.license_ref,
                        });
                    }
                }
            }

            if let Some(concluded_license) = &package.concluded_license {
                for license in concluded_license.licenses() {
                    if license.license_ref.clone() {
                        let license_ref_id = get_license_ref_id_from_extracted_licensing_info(
                            format!("LicenseRef-{}", license.identifier.clone().to_string()),
                            self.sbom.sbom_id.clone(),
                            extracted_licensing_info_list.clone(),
                        );
                        licenses.add(&LicenseInfo {
                            license: format!("LicenseRef-{}", license.identifier.to_string()),
                            license_category: LicenseCategory::SPDXCONCLUDED,
                            license_name: license.identifier.clone().to_string(),
                            license_ref_id,
                            is_license_ref: license.license_ref,
                        });
                    } else {
                        licenses.add(&LicenseInfo {
                            license: license.identifier.to_string(),
                            license_category: LicenseCategory::SPDXCONCLUDED,
                            license_name: license.identifier.clone().to_string(),
                            license_ref_id: None,
                            is_license_ref: license.license_ref,
                        });
                    }
                }
            }

            let mut refs = Vec::new();

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
                licenses.get_license_copy(),
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
                        db,
                    )
                    .await?;

                if let Some(ver) = package.package_version.clone() {
                    pr.ingest_product_version(ver, Some(self.sbom.sbom_id), db)
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

        license_refs.create(db).await?;
        // create all purls and CPEs
        licenses.create(db).await?;
        purls.create(db).await?;
        cpes.create(db).await?;

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

        packages.create(db).await?;
        files.create(db).await?;
        relationships.create(db).await?;

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
