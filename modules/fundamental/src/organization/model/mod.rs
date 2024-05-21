use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

mod details;
mod summary;

use crate::Error;
pub use details::*;
pub use summary::*;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::organization;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct OrganizationHead {
    pub id: i32,
    pub name: String,
    pub cpe_key: Option<String>,
    pub website: Option<String>,
}

impl OrganizationHead {
    pub async fn from_entity(
        organization: &organization::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(OrganizationHead {
            id: organization.id,
            name: organization.name.clone(),
            cpe_key: organization.cpe_key.clone(),
            website: organization.website.clone(),
        })
    }
}
