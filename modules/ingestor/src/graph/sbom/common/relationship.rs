use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use sea_query::OnConflict;
use std::collections::HashSet;
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

    /// Pre-flight check to see if all relationships can be inserted.
    ///
    /// This expects a source of references to check against. If creating a fresh set of nodes and
    /// relationships, these sources would most likely be the creators (like [`super::PackageCreator`]).
    /// If nodes already exist in the database, those nodes would need to be extracted and provided.
    pub fn validate<'s, I>(&self, sources: I) -> Result<(), anyhow::Error>
    where
        I: IntoIterator<Item = &'s dyn ReferenceSource>,
    {
        let mut refs = HashSet::new();

        for source in sources.into_iter() {
            source.extend_into(&mut refs);
        }

        for rel in &self.rels {
            if let Set(left) = &rel.left_node_id {
                if !refs.contains(left.as_str()) {
                    // TODO: raise error
                }
            }
            if let Set(right) = &rel.right_node_id {
                if !refs.contains(right.as_str()) {
                    // TODO: raise error
                }
            }
        }

        Ok(())
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

/// A source of SBOM node references for validating.
pub trait ReferenceSource {
    fn extend_into<'s>(&'s self, e: &'s mut dyn Extend<&'s str>);
}

/*
impl<'s> ReferenceSource for &[&'s str] {
    fn extend_into<'s, E: Extend<&'s str>>(&self, e: &'s mut E) {
        e.extend(self)
    }
}
*/
