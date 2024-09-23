use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

mod details;
mod summary;

use crate::Error;
pub use details::*;
pub use summary::*;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::organization;

/// An organization who may issue advisories, product SBOMs, or
/// otherwise be involved in supply-chain evidence.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
pub struct OrganizationHead {
    /// The opaque UUID of the organization.
    pub id: Uuid,

    /// The name of the organization.
    pub name: String,

    /// The `CPE` key of the organization, if known.
    #[schema(required)]
    pub cpe_key: Option<String>,

    /// The website of the organization, if known.
    #[schema(required)]
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
