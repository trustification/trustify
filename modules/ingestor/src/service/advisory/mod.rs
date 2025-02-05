use std::collections::HashMap;

use crate::graph::error::Error;
use sea_orm::ConnectionTrait;
use sea_orm::EntityTrait;
use trustify_entity::status;
use uuid::Uuid;

pub mod csaf;
pub mod cve;
pub mod osv;

#[derive(Debug, Clone)]
pub struct StatusCache {
    pub cache: HashMap<String, Uuid>,
}

impl StatusCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub async fn load_statuses(&mut self, connection: &impl ConnectionTrait) -> Result<(), Error> {
        self.cache.clear();
        let statuses = status::Entity::find().all(connection).await?;
        statuses
            .iter()
            .map(|s| self.cache.insert(s.slug.clone(), s.id))
            .for_each(drop);

        Ok(())
    }

    pub async fn get_status_id(
        &mut self,
        status: &str,
        connection: &impl ConnectionTrait,
    ) -> Result<Uuid, Error> {
        if let Some(s) = self.cache.get(status) {
            return Ok(*s);
        }

        // If not found, reload the cache and check again
        self.load_statuses(connection).await?;

        self.cache
            .get(status)
            .cloned()
            .ok_or_else(|| crate::graph::error::Error::InvalidStatus(status.to_string()))
    }
}

impl Default for StatusCache {
    fn default() -> Self {
        Self::new()
    }
}
