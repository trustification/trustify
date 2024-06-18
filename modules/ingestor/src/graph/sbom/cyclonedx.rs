use crate::graph::{
    purl::creator::PurlCreator,
    sbom::{PackageCreator, PackageReference, SbomContext, SbomInformation},
    Graph,
};
use cyclonedx_bom::prelude::{Bom, Component, Components};
use sea_orm::ConnectionTrait;
use std::str::FromStr;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tracing::instrument;
use trustify_common::{cpe::Cpe, db::Transactional, purl::Purl};
use trustify_entity::relationship::Relationship;
use uuid::Uuid;

/// Marker we use for identifying the document itself.
///
/// Similar to the SPDX doc id, which is attached to the document itself. CycloneDX doesn't have
/// such a concept, but can still attach a component to the document via a dedicated metadata
/// component.
const CYCLONEDX_DOC_REF: &str = "CycloneDX-doc-ref";

pub struct Information<'a>(pub &'a Bom);

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
            .unwrap_or_else(|| sbom.version.to_string());

        Self {
            node_id: CYCLONEDX_DOC_REF.to_string(),
            name,
            published,
            authors,
        }
    }
}

impl SbomContext {
    #[instrument(skip(tx, sbom), err)]
    pub async fn ingest_cyclonedx<TX: AsRef<Transactional>>(
        &self,
        sbom: Bom,
        tx: TX,
    ) -> Result<(), anyhow::Error> {
        let db = &self.graph.db.connection(&tx);

        let mut creator = Creator::new(self.sbom.sbom_id);

        if let Some(metadata) = &sbom.metadata {
            if let Some(component) = &metadata.component {
                creator.add(component);
                if let Some(r#ref) = &component.bom_ref {
                    creator.relate(
                        CYCLONEDX_DOC_REF.to_string(),
                        Relationship::DescribedBy,
                        r#ref.to_string(),
                    );
                }
            }
        }

        creator.add_all(&sbom.components);

        for left in sbom.dependencies.iter().flat_map(|e| &e.0) {
            for right in &left.dependencies {
                creator.relate(
                    right.clone(),
                    Relationship::DependencyOf,
                    left.dependency_ref.clone(),
                );
            }
        }

        creator.create(&self.graph, &tx, db).await?;

        Ok(())
    }
}

/// Creator of CycloneDX components and dependencies
#[derive(Debug, Default)]
struct Creator<'a> {
    sbom_id: Uuid,
    components: Vec<&'a Component>,
    relations: Vec<(String, Relationship, String)>,
}

impl<'a> Creator<'a> {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            components: Default::default(),
            relations: Default::default(),
        }
    }

    pub fn add_all(&mut self, components: impl Into<Option<&'a Components>>) {
        if let Some(components) = components.into() {
            self.extend(&components.0)
        }
    }

    pub fn add(&mut self, component: &'a Component) {
        self.components.push(component);
        self.add_all(&component.components)
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

    pub async fn create(
        self,
        graph: &Graph,
        tx: impl AsRef<Transactional>,
        db: &impl ConnectionTrait,
    ) -> anyhow::Result<()> {
        let mut purls = PurlCreator::new();
        let mut packages = PackageCreator::with_capacity(
            self.sbom_id,
            self.components.len(),
            self.relations.len(),
        );

        for comp in self.components {
            let node_id = comp
                .bom_ref
                .as_ref()
                .cloned()
                .unwrap_or_else(|| comp.name.to_string());

            let mut refs = vec![];

            if let Some(purl) = &comp.purl {
                if let Ok(purl) = Purl::from_str(purl.as_ref()) {
                    refs.push(PackageReference::Purl(purl.qualifier_uuid()));
                    purls.add(purl);
                }
            }
            if let Some(cpe) = &comp.cpe {
                if let Ok(cpe) = Cpe::from_str(cpe.as_ref()) {
                    let cpe = graph.ingest_cpe22(cpe, &tx).await?;
                    refs.push(PackageReference::Cpe(cpe.cpe.id));
                }
            }

            packages.add(
                node_id,
                comp.name.to_string(),
                comp.version.as_ref().map(|v| v.to_string()),
                refs,
            );
        }

        for (left, rel, right) in self.relations {
            packages.relate(left, rel, right);
        }

        purls.create(db).await?;
        packages.create(db).await?;

        Ok(())
    }
}
