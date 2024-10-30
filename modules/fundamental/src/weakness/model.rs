use crate::Error;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::weakness;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct WeaknessHead {
    pub id: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct WeaknessSummary {
    #[serde(flatten)]
    pub head: WeaknessHead,
}

impl WeaknessSummary {
    pub async fn from_entities(
        entities: &[weakness::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();
        for each in entities {
            summaries.push(Self::from_entity(each, tx).await?)
        }

        Ok(summaries)
    }

    pub async fn from_entity(
        entity: &weakness::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            head: WeaknessHead {
                id: entity.id.clone(),
                description: entity.description.clone(),
            },
        })
    }
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct WeaknessDetails {
    #[serde(flatten)]
    pub head: WeaknessHead,
    pub extended_description: Option<String>,
    pub child_of: Option<Vec<String>>,
    pub parent_of: Option<Vec<String>>,
    pub starts_with: Option<Vec<String>>,
    pub can_follow: Option<Vec<String>>,
    pub can_precede: Option<Vec<String>>,
    pub required_by: Option<Vec<String>>,
    pub requires: Option<Vec<String>>,
    pub can_also_be: Option<Vec<String>>,
    pub peer_of: Option<Vec<String>>,
}

impl WeaknessDetails {
    pub async fn from_entity(
        entity: &weakness::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            head: WeaknessHead {
                id: entity.id.clone(),
                description: entity.description.clone(),
            },
            extended_description: entity.extended_description.clone(),
            child_of: entity.child_of.clone(),
            parent_of: entity.parent_of.clone(),
            starts_with: entity.starts_with.clone(),
            can_follow: entity.can_follow.clone(),
            can_precede: entity.can_precede.clone(),
            required_by: entity.required_by.clone(),
            requires: entity.requires.clone(),
            can_also_be: entity.can_also_be.clone(),
            peer_of: entity.peer_of.clone(),
        })
    }
}
