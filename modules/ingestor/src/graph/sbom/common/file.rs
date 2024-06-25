use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{sbom_file, sbom_node};
use uuid::Uuid;

// Creator of files and relationships.
pub struct FileCreator {
    sbom_id: Uuid,
    nodes: Vec<sbom_node::ActiveModel>,
    files: Vec<sbom_file::ActiveModel>,
}

impl FileCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            nodes: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_files: usize) -> Self {
        Self {
            sbom_id,
            nodes: Vec::with_capacity(capacity_files),
            files: Vec::with_capacity(capacity_files),
        }
    }

    pub fn add(&mut self, node_id: String, name: String) {
        self.nodes.push(sbom_node::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id.clone()),
            name: Set(name),
        });

        self.files.push(sbom_file::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(node_id),
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

        for batch in &self.files.into_iter().chunked() {
            sbom_file::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([sbom_file::Column::SbomId, sbom_file::Column::NodeId])
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
