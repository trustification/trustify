use crate::Error;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use time::OffsetDateTime;
use trustify_common::id::{Id, IdError};
use trustify_entity::source_document;
use trustify_module_storage::service::StorageKey;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SourceDocument {
    pub sha256: String,
    pub sha384: String,
    pub sha512: String,
    pub size: u64,
    /// The timestamp the document was ingested
    #[serde(with = "time::serde::rfc3339")]
    pub ingested: OffsetDateTime,
}

impl SourceDocument {
    pub async fn from_entity(source_document: &source_document::Model) -> Result<Self, Error> {
        Ok(Self {
            sha256: format!("sha256:{}", source_document.sha256),
            sha384: format!("sha384:{}", source_document.sha384),
            sha512: format!("sha512:{}", source_document.sha512),
            size: source_document.size as u64,
            ingested: source_document.ingested,
        })
    }
}

impl TryInto<StorageKey> for &SourceDocument {
    type Error = IdError;

    fn try_into(self) -> Result<StorageKey, Self::Error> {
        if let Ok(key) = Id::from_str(&self.sha256)?.try_into() {
            return Ok(key);
        }

        if let Ok(key) = Id::from_str(&self.sha384)?.try_into() {
            return Ok(key);
        }

        if let Ok(key) = Id::from_str(&self.sha512)?.try_into() {
            return Ok(key);
        }

        Err(IdError::MissingPrefix)
    }
}

impl TryInto<StorageKey> for SourceDocument {
    type Error = IdError;

    fn try_into(self) -> Result<StorageKey, Self::Error> {
        (&self).try_into()
    }
}
