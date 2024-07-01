use crate::package::model::PackageHead;
use crate::Error;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_entity::base_purl;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PackageSummary {
    #[serde(flatten)]
    pub head: PackageHead,
}

impl PackageSummary {
    pub async fn from_entities(
        entities: &Vec<base_purl::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        for entity in entities {
            summaries.push(PackageSummary {
                head: PackageHead::from_entity(entity, tx).await?,
            })
        }

        Ok(summaries)
    }
}

paginated!(PackageSummary);
