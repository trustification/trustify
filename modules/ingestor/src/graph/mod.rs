pub mod advisory;
pub mod cpe;
pub mod db_context;
pub mod error;
pub mod organization;
pub mod product;
pub mod purl;
pub mod sbom;
pub mod vulnerability;

use db_context::DbContext;
use sea_orm::DbErr;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Graph {
    pub(crate) db: trustify_common::db::Database,
    pub(crate) db_context: Arc<Mutex<DbContext>>,
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
        Self {
            db,
            db_context: Arc::new(Mutex::new(DbContext::new())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Existed(T),
    Added(T),
}

impl<T> Outcome<T> {
    pub fn into_inner(self) -> T {
        match self {
            Outcome::Existed(value) => value,
            Outcome::Added(value) => value,
        }
    }
}

impl<T> Deref for Outcome<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Outcome::Existed(value) => value,
            Outcome::Added(value) => value,
        }
    }
}

impl<T> DerefMut for Outcome<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Outcome::Existed(value) => value,
            Outcome::Added(value) => value,
        }
    }
}
