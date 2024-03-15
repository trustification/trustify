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

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paginated {
    #[serde(default = "default::page_size")]
    pub page_size: NonZeroU64,
    #[serde(default)]
    pub page: u64,
}

mod default {
    use std::num::NonZeroU64;

    #[allow(clippy::unwrap_used)]
    pub(super) fn page_size() -> NonZeroU64 {
        NonZeroU64::new(50).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResults<R> {
    pub results: Vec<R>,
    pub page: u64,
    pub page_size: NonZeroU64,
    pub number_of_items: u64,
    pub number_of_pages: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_page: Option<Paginated>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page: Option<Paginated>,
}

impl<R> PaginatedResults<R> {
    /// Create a new paginated result
    pub async fn new<'c, C, S>(
        paginated: Paginated,
        results: Vec<R>,
        paginator: &sea_orm::Paginator<'c, C, S>,
    ) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
        S: SelectorTrait,
    {
        let ItemsAndPagesNumber {
            number_of_items,
            number_of_pages,
        } = paginator.num_items_and_pages().await?;

        Ok(PaginatedResults {
            results,
            page: paginator.cur_page(),
            page_size: paginated.page_size,
            number_of_items,
            number_of_pages,
            previous_page: if paginated.page > 0 {
                Some(Paginated {
                    page_size: paginated.page_size,
                    page: paginated.page - 1,
                })
            } else {
                None
            },
            next_page: if paginated.page + 1 < number_of_pages {
                Some(Paginated {
                    page_size: paginated.page_size,
                    page: paginated.page + 1,
                })
            } else {
                None
            },
        })
    }
}
