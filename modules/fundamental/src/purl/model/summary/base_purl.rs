use crate::purl::model::BasePurlHead;
use crate::Error;
use serde::{Deserialize, Serialize};
use trustify_entity::base_purl;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct BasePurlSummary {
    #[serde(flatten)]
    pub head: BasePurlHead,
}

impl BasePurlSummary {
    pub async fn from_entities(entities: &Vec<base_purl::Model>) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        for entity in entities {
            summaries.push(BasePurlSummary {
                head: BasePurlHead::from_entity(entity).await?,
            })
        }

        Ok(summaries)
    }
}
