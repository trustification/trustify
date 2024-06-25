use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{package_relates_to_package, relationship::Relationship};
use uuid::Uuid;

// Creator of relationships.
pub struct RelationshipCreator {
    sbom_id: Uuid,
    rels: Vec<package_relates_to_package::ActiveModel>,
}

impl RelationshipCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,

            rels: Vec::new(),
        }
    }

    pub fn with_capacity(sbom_id: Uuid, capacity_rel: usize) -> Self {
        Self {
            sbom_id,

            rels: Vec::with_capacity(capacity_rel),
        }
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
