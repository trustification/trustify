use crate::db::limiter::Limiter;
use sea_orm::{ConnectionTrait, DbErr, ItemsAndPagesNumber, SelectorTrait};
use serde::{Serialize, Serializer};
use std::num::NonZeroU64;
use utoipa::ToSchema;

/// A struct wrapping an item with a revision.
///
/// If the revision should not be part of the payload, but e.g. an HTTP header (like `ETag`), this
/// struct can help carrying both pieces.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct Revisioned<T> {
    /// The actual value
    pub value: T,
    /// The revision.
    ///
    /// An opaque string that should have no meaning to the user, only to the backend.
    pub revision: String,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paginated {
    /// The first item to return, skipping all that come before it.
    ///
    /// NOTE: The order of items is defined by the API being called.
    #[serde(default)]
    pub offset: u64,
    /// The maximum number of entries to return.
    ///
    /// Zero means: no limit
    #[serde(default)]
    pub limit: u64,
}

mod default {
    use std::num::NonZeroU64;

    #[allow(clippy::unwrap_used)]
    pub(super) fn page_size() -> NonZeroU64 {
        NonZeroU64::new(50).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResults<R> {
    pub items: Vec<R>,
    pub total: u64,
}

impl<R> PaginatedResults<R> {
    /// Create a new paginated result
    pub async fn new<C, S>(limiter: Limiter<'_, C, S>) -> Result<PaginatedResults<S::Item>, DbErr>
    where
        C: ConnectionTrait,
        S: SelectorTrait,
    {
        let total = limiter.total().await?;
        let results = limiter.fetch().await?;

        Ok(PaginatedResults {
            items: results,
            total,
        })
    }
}
