use anyhow::Context;
use log::debug;
use migration::Migrator;
use postgresql_embedded;
use postgresql_embedded::PostgreSQL;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, DbErr,
    Statement, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;
use tempfile::TempDir;
use trustify_common::db::{ConnectionOrTransaction, Transactional};

mod cpe22;

pub mod advisory;
pub mod error;
pub mod package;
pub mod sbom;
pub mod vulnerability;

#[derive(Debug, Clone)]
pub struct Graph {
    db: trustify_common::db::Database,
}

pub enum Error<E: Send> {
    Database(DbErr),
    Transaction(E),
}

impl<E: Send> From<DbErr> for Error<E> {
    fn from(value: DbErr) -> Self {
        Self::Database(value)
    }
}

impl<E: Send> Debug for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transaction(_) => f.debug_tuple("Transaction").finish(),
            Self::Database(err) => f.debug_tuple("Database").field(err).finish(),
        }
    }
}

impl<E: Send + Display> std::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transaction(inner) => write!(f, "transaction error: {}", inner),
            Self::Database(err) => write!(f, "database error: {err}"),
        }
    }
}

impl<E: Send + Display> std::error::Error for Error<E> {}

impl Graph {
    pub fn new(db: trustify_common::db::Database) -> Self {
        Self { db }
    }

    /// Create a `Transactional::Some(_)` with a new transaction.
    ///
    /// The transaction will be rolled-back unless explicitly `commit()`'d before
    /// it drops.
    pub async fn transaction(&self) -> Result<Transactional, error::Error> {
        Ok(Transactional::Some(self.db.begin().await?))
    }

    pub(crate) fn connection<'db, TX: AsRef<Transactional>>(
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
