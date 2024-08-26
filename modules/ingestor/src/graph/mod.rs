pub mod advisory;
pub mod cpe;
pub mod error;
pub mod organization;
pub mod product;
pub mod purl;
pub mod sbom;
pub mod vulnerability;

use sea_orm::{DbErr, TransactionTrait};
use std::fmt::Debug;
use tracing::instrument;
use trustify_common::db::{ConnectionOrTransaction, Transactional};

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

    /// Create a `Transactional::Some(_)` with a new transaction.
    ///
    /// The transaction will be rolled-back unless explicitly `commit()`'d before
    /// it drops.
    #[instrument]
    pub async fn transaction(&self) -> Result<Transactional, error::Error> {
        Ok(Transactional::Some(self.db.begin().await?))
    }

    pub fn connection<'db, TX: AsRef<Transactional>>(
        &'db self,
        tx: &'db TX,
    ) -> ConnectionOrTransaction {
        match tx.as_ref() {
            Transactional::None => ConnectionOrTransaction::Connection(&self.db),
            Transactional::Some(tx) => ConnectionOrTransaction::Transaction(tx),
        }
    }

    pub async fn close(self) -> anyhow::Result<()> {
        self.db.close().await
    }

    /// Ping the database.
    ///
    /// Intended to be used for health checks.
    pub async fn ping(&self) -> anyhow::Result<()> {
        self.db.ping().await
    }
}
