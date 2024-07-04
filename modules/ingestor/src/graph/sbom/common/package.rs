use crate::graph::sbom::ReferenceSource;
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{sbom_node, sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref};
use uuid::Uuid;

// Creator of packages and relationships.
pub struct PackageCreator {
    sbom_id: Uuid,
    nodes: Vec<sbom_node::ActiveModel>,
    packages: Vec<sbom_package::ActiveModel>,
    purl_refs: Vec<sbom_package_purl_ref::ActiveModel>,
    cpe_refs: Vec<sbom_package_cpe_ref::ActiveModel>,
}

pub enum PackageReference {
    Purl(Uuid),
    Cpe(Uuid),
}

impl PackageCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: Vec::new(),
            packages: Vec::new(),
            purl_refs: Vec::new(),
            cpe_refs: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_packages: usize) -> Self {
        Self {
            sbom_id,
            nodes: Vec::with_capacity(capacity_packages),
            packages: Vec::with_capacity(capacity_packages),
            purl_refs: Vec::with_capacity(capacity_packages),
            cpe_refs: Vec::new(), // most packages won't have a CPE, so we start with a low number
        }
    }

    pub fn add(
        &mut self,
        node_id: String,
        name: String,
        version: Option<String>,
        refs: impl IntoIterator<Item = PackageReference>,
    ) {
        for r#ref in refs {
            match r#ref {
                PackageReference::Cpe(cpe) => {
                    self.cpe_refs.push(sbom_package_cpe_ref::ActiveModel {
                        sbom_id: Set(self.sbom_id),
                        node_id: Set(node_id.clone()),
                        cpe_id: Set(cpe),
                    });
                }
                PackageReference::Purl(purl) => {
                    self.purl_refs.push(sbom_package_purl_ref::ActiveModel {
                        sbom_id: Set(self.sbom_id),
                        node_id: Set(node_id.clone()),
                        qualified_purl_id: Set(purl),
                    });
                }
            }
        }

        self.nodes.push(sbom_node::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id.clone()),
            name: Set(name),
        });

        self.packages.push(sbom_package::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
            version: Set(version),
        });
    }

    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), anyhow::Error> {
        for batch in &self.nodes.into_iter().chunked() {
            sbom_node::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_node::Column::SbomId, sbom_node::Column::NodeId])
                        .do_nothing()
                        .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        for batch in &self.packages.into_iter().chunked() {
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
                .exec(db)
                .await?;
        }

        for batch in &self.purl_refs.into_iter().chunked() {
            sbom_package_purl_ref::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        sbom_package_purl_ref::Column::SbomId,
                        sbom_package_purl_ref::Column::NodeId,
                        sbom_package_purl_ref::Column::QualifiedPurlId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        for batch in &self.cpe_refs.into_iter().chunked() {
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
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

impl<'a> ReferenceSource<'a> for PackageCreator {
    fn references(&'a self) -> impl IntoIterator<Item = &'a str> {
        self.nodes
            .iter()
            .filter_map(move |node| match &node.node_id {
                Set(node_id) => Some(node_id.as_str()),
                _ => None,
            })
    }
}
