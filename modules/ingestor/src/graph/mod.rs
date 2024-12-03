pub mod advisory;
pub mod cpe;
pub mod error;
pub mod organization;
pub mod product;
pub mod purl;
pub mod sbom;
pub mod vulnerability;

use sea_orm::DbErr;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct Graph {
    pub(crate) db: trustify_common::db::Database,
}

#[derive(Debug, thiserror::Error)]
pub enum Error<E: Send> {
    #[error(transparent)]
    Database(#[from] DbErr),
    #[error(transparent)]
    Transaction(E),
}

impl Graph {
    pub fn new(db: trustify_common::db::Database) -> Self {
        Self { db }
    }
}
