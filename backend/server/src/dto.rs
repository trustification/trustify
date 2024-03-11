use serde::{Deserialize, Serialize};
use trustify_entity as entity;

#[derive(Serialize, Deserialize)]
pub struct AdvisoryDto {
    pub id: i32,
    // pub aggregated_severity: String,
    // pub revision_date: String,
}

impl From<entity::advisory::Model> for AdvisoryDto {
    fn from(value: entity::advisory::Model) -> Self {
        Self { id: value.id }
    }
}
