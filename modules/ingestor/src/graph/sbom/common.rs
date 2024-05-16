use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom_node, sbom_package,
    sbom_package_cpe_ref, sbom_package_purl_ref,
};
use uuid::Uuid;

// Creator of packages and relationships.
pub struct PackageCreator {
    sbom_id: Uuid,
    nodes: Vec<sbom_node::ActiveModel>,
    packages: Vec<sbom_package::ActiveModel>,
    purl_refs: Vec<sbom_package_purl_ref::ActiveModel>,
    cpe_refs: Vec<sbom_package_cpe_ref::ActiveModel>,
    rels: Vec<package_relates_to_package::ActiveModel>,
}

pub enum PackageReference {
    Purl(Uuid),
    Cpe(i32),
}

impl PackageCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: Vec::new(),
            packages: Vec::new(),
            purl_refs: Vec::new(),
            cpe_refs: Vec::new(),
            rels: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_packages: usize, capacity_rel: usize) -> Self {
        Self {
            sbom_id,
            nodes: Vec::with_capacity(capacity_packages),
            packages: Vec::with_capacity(capacity_packages),
            purl_refs: Vec::with_capacity(capacity_packages),
            cpe_refs: Vec::new(), // most packages won't have a CPE, so we start with a low number
            rels: Vec::with_capacity(capacity_rel),
        }
    }

    pub fn add(
        &mut self,
        node_id: String,
        name: String,
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
                        qualified_package_id: Set(purl),
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
        });
    }

    pub fn relate(&mut self, left: String, rel: Relationship, right: String) {
        self.rels.push(package_relates_to_package::ActiveModel {
            sbom_id: Set(self.sbom_id),
            left_node_id: Set(left),
            relationship: Set(rel),
            right_node_id: Set(right),
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
                        sbom_package_purl_ref::Column::QualifiedPackageId,
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

        for batch in &self.rels.into_iter().chunked() {
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
                .exec(db)
                .await?;
        }

        Ok(())
    }
}
