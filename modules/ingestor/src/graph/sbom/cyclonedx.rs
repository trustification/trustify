use crate::graph::{
    cpe::CpeCreator,
    product::ProductInformation,
    purl::creator::PurlCreator,
    sbom::{
        LicenseCreator, LicenseInfo, PackageCreator, PackageReference, RelationshipCreator,
        SbomContext, SbomInformation,
    },
};
use sea_orm::ConnectionTrait;
use serde_cyclonedx::cyclonedx::v_1_6::{Component, CycloneDx, LicenseChoiceUrl};
use std::{collections::HashMap, str::FromStr};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;
use uuid::Uuid;

/// Marker we use for identifying the document itself.
///
/// Similar to the SPDX doc id, which is attached to the document itself. CycloneDX doesn't have
/// such a concept, but can still attach a component to the document via a dedicated metadata
/// component.
const CYCLONEDX_DOC_REF: &str = "CycloneDX-doc-ref";

pub struct Information<'a>(pub &'a CycloneDx);

impl<'a> From<Information<'a>> for SbomInformation {
    fn from(value: Information<'a>) -> Self {
        let sbom = value.0;

        let published = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.timestamp.as_ref())
            .and_then(|timestamp| {
                OffsetDateTime::parse(timestamp.as_ref(), &Iso8601::DEFAULT).ok()
            });

        let authors = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.authors.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|author| match (&author.name, &author.email) {
                (Some(name), Some(email)) => Some(format!("{name} <{email}>")),
                (Some(name), None) => Some(name.to_string()),
                (None, Some(email)) => Some(email.to_string()),
                (None, None) => None,
            })
            .collect();

        let name = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.component.as_ref())
            .map(|component| component.name.to_string())
            // otherwise use the serial number
            .or_else(|| sbom.serial_number.as_ref().map(|id| id.to_string()))
            // TODO: not sure what to use instead, the version will most likely be `1`.
            .or_else(|| sbom.version.as_ref().map(|v| v.to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        let data_licenses = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.licenses.as_ref())
            .into_iter()
            .flat_map(|licenses| match licenses {
                LicenseChoiceUrl::Variant0(license) => license
                    .iter()
                    .flat_map(|l| l.license.id.as_ref().or(l.license.name.as_ref()).cloned())
                    .collect::<Vec<_>>(),
                LicenseChoiceUrl::Variant1(license) => {
                    license.iter().map(|l| l.expression.clone()).collect()
                }
            })
            .collect();

        Self {
            node_id: CYCLONEDX_DOC_REF.to_string(),
            name,
            published,
            authors,
            data_licenses,
        }
    }
}

impl SbomContext {
    #[instrument(skip(connection, sbom), ret)]
    pub async fn ingest_cyclonedx<C: ConnectionTrait>(
        &self,
        mut sbom: CycloneDx,
        connection: &C,
    ) -> Result<(), anyhow::Error> {
        let mut license_creator = LicenseCreator::new();
        let mut creator = Creator::new(self.sbom.sbom_id);

        // extract "describes"

        if let Some(metadata) = &mut sbom.metadata {
            if let Some(component) = &mut metadata.component {
                let bom_ref = component
                    .bom_ref
                    .get_or_insert_with(|| Uuid::new_v4().to_string())
                    .to_string();

                let product_cpe = component
                    .cpe
                    .as_ref()
                    .map(|cpe| Cpe::from_str(cpe.as_ref()))
                    .transpose()?;
                let pr = self
                    .graph
                    .ingest_product(
                        component.name.clone(),
                        ProductInformation {
                            vendor: component.publisher.clone().map(|p| p.to_string()),
                            cpe: product_cpe,
                        },
                        connection,
                    )
                    .await?;

                if let Some(ver) = component.version.clone() {
                    pr.ingest_product_version(ver.to_string(), Some(self.sbom.sbom_id), connection)
                        .await?;
                }

                // create component

                creator.add(component);

                // create a relationship

                creator.relate(
                    bom_ref,
                    Relationship::DescribedBy,
                    CYCLONEDX_DOC_REF.to_string(),
                );
            }
        }

        // record components

        creator.add_all(&sbom.components);

        // record licenses

        for component in sbom.components.iter().flatten() {
            if let Some(licenses) = &component.licenses {
                match licenses {
                    LicenseChoiceUrl::Variant0(licenses) => {
                        'l: for license in licenses {
                            let license = if let Some(id) = license.license.id.clone() {
                                id
                            } else if let Some(name) = license.license.name.clone() {
                                name
                            } else {
                                continue 'l;
                            };

                            let license = LicenseInfo {
                                license,
                                refs: Default::default(),
                            };

                            license_creator.add(&license);
                            creator.add_license_relation(component, &license);
                        }
                    }
                    LicenseChoiceUrl::Variant1(licenses) => {
                        for license in licenses {
                            let license = LicenseInfo {
                                license: license.expression.clone(),
                                refs: Default::default(),
                            };

                            license_creator.add(&license);
                            creator.add_license_relation(component, &license);
                        }
                    }
                }
            }
        }

        // create relationships

        for left in sbom.dependencies.iter().flatten() {
            for right in left.depends_on.iter().flatten() {
                creator.relate(right.clone(), Relationship::DependencyOf, left.ref_.clone());
            }
        }

        // create

        license_creator.create(connection).await?;
        creator.create(connection).await?;

        // done

        Ok(())
    }
}

/// Creator of CycloneDX components and dependencies
#[derive(Debug, Default)]
struct Creator<'a> {
    sbom_id: Uuid,
    components: Vec<&'a Component>,
    relations: Vec<(String, Relationship, String)>,
    license_relations: HashMap<String, Vec<LicenseInfo>>,
}

impl<'a> Creator<'a> {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            components: Default::default(),
            relations: Default::default(),
            license_relations: Default::default(),
        }
    }

    pub fn add_all(&mut self, components: &'a Option<Vec<Component>>) {
        self.extend(components.iter().flatten())
    }

    pub fn add(&mut self, component: &'a Component) {
        self.components.push(component);
        self.extend(component.components.iter().flatten());
    }

    pub fn add_license_relation(&mut self, component: &'a Component, license: &LicenseInfo) {
        let node_id = component
            .bom_ref
            .as_ref()
            .cloned()
            .unwrap_or_else(|| component.name.to_string());

        self.license_relations
            .entry(node_id)
            .or_default()
            .push(license.clone());
    }

    pub fn extend<I>(&mut self, i: I)
    where
        I: IntoIterator<Item = &'a Component>,
    {
        for c in i.into_iter() {
            self.add(c);
        }
    }

    pub fn relate(&mut self, left: String, rel: Relationship, right: String) {
        self.relations.push((left, rel, right));
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> anyhow::Result<()> {
        let mut purls = PurlCreator::new();
        let mut cpes = CpeCreator::new();
        let mut packages = PackageCreator::with_capacity(self.sbom_id, self.components.len());
        let mut relationships =
            RelationshipCreator::with_capacity(self.sbom_id, self.relations.len());

        for comp in self.components {
            let node_id = comp
                .bom_ref
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            let mut refs = vec![];

            if let Some(purl) = &comp.purl {
                if let Ok(purl) = Purl::from_str(purl.as_ref()) {
                    refs.push(PackageReference::Purl {
                        versioned_purl: purl.version_uuid(),
                        qualified_purl: purl.qualifier_uuid(),
                    });
                    purls.add(purl);
                }
            }
            if let Some(cpe) = &comp.cpe {
                if let Ok(cpe) = Cpe::from_str(cpe.as_ref()) {
                    let id = cpe.uuid();
                    cpes.add(cpe);
                    refs.push(PackageReference::Cpe(id));
                }
            }

            let license_refs = self
                .license_relations
                .get(&node_id)
                .cloned()
                .unwrap_or_default();

            packages.add(
                node_id,
                comp.name.to_string(),
                comp.version.as_ref().map(|v| v.to_string()),
                refs,
                license_refs,
            );
        }

        for (left, rel, right) in self.relations {
            relationships.relate(left, rel, right);
        }

        purls.create(db).await?;
        cpes.create(db).await?;
        packages.create(db).await?;
        relationships.create(db).await?;

        Ok(())
    }
}
