mod func;

pub mod chunk;
pub mod embedded;
pub mod limiter;
pub mod multi_model;
pub mod query;

pub use func::*;

use anyhow::{ensure, Context};
use migration::{Migrator, MigratorTrait};
use sea_orm::{
    prelude::async_trait, ConnectOptions, ConnectionTrait, DatabaseConnection, DbBackend, DbErr,
    ExecResult, QueryResult, RuntimeErr, Statement,
};
use sqlx::error::ErrorKind;
use std::ops::{Deref, DerefMut};
use tracing::instrument;

#[derive(Clone, Debug)]
pub struct Database {
    /// the database connection
    db: DatabaseConnection,
    /// the database name
    name: String,
}

impl Database {
    #[instrument(err)]
    pub async fn new(database: &crate::config::Database) -> Result<Self, anyhow::Error> {
        let url = database.to_url();
        log::debug!("connect to {}", url);

        let mut opt = ConnectOptions::new(url);
        opt.max_connections(database.max_conn);
        opt.min_connections(database.min_conn);
        opt.sqlx_logging_level(log::LevelFilter::Trace);

        let db = sea_orm::Database::connect(opt).await?;
        let name = database.name.clone();

        Ok(Self { db, name })
    }

    #[instrument(skip(self), err)]
    pub async fn migrate(&self) -> Result<(), anyhow::Error> {
        log::debug!("applying migrations");
        Migrator::up(&self.db, None).await?;
        log::debug!("applied migrations");

        Ok(())
    }

    #[instrument(skip(self), err)]
    pub async fn refresh(&self) -> Result<(), anyhow::Error> {
        log::warn!("refreshing database schema...");
        Migrator::refresh(&self.db).await?;
        log::warn!("refreshing database schema... done!");

        Ok(())
    }

    #[instrument(err)]
    pub async fn bootstrap(database: &crate::config::Database) -> Result<Self, anyhow::Error> {
        ensure!(
            database.url.is_none(),
            "Unable to bootstrap database with '--db-url'"
        );

        let url = crate::config::Database {
            name: "postgres".into(),
            ..database.clone()
        }
        .to_url();

        log::debug!("bootstrap to {}", url);
        let db = sea_orm::Database::connect(url).await?;

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("DROP DATABASE IF EXISTS \"{}\";", database.name),
        ))
        .await?;

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("CREATE DATABASE \"{}\";", database.name),
        ))
        .await?;
        db.close().await?;

        let db = Self::new(database).await?;
        db.execute_unprepared("CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\";")
            .await?;
        db.migrate().await?;

        Ok(db)
    }

    #[instrument(skip(self), err)]
    pub async fn close(self) -> anyhow::Result<()> {
        Ok(self.db.close().await?)
    }

    /// Ping the database.
    ///
    /// Intended to be used for health checks.
    #[instrument(skip(self), err)]
    pub async fn ping(&self) -> anyhow::Result<()> {
        self.db
            .ping()
            .await
            .context("failed to ping the database")?;
        Ok(())
    }

    /// Get the name of the database
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Deref for Database {
    type Target = DatabaseConnection;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for Database {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

/// Implementation of the connection trait for our database struct.
///
/// **NOTE**: We lack the implementations for the `mock` feature. However, the mock feature would
/// require us to have the `Database` struct to be non-clone, which we don't support anyway.
#[async_trait::async_trait]
impl ConnectionTrait for Database {
    fn get_database_backend(&self) -> DbBackend {
        self.db.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.db.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.db.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.db.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.db.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.db.support_returning()
    }
}

/// Implementation of the connection trait for our database struct.
///
/// **NOTE**: We lack the implementations for the `mock` feature. However, the mock feature would
/// require us to have the `Database` struct to be non-clone, which we don't support anyway.
#[async_trait::async_trait]
impl ConnectionTrait for &Database {
    fn get_database_backend(&self) -> DbBackend {
        self.db.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.db.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.db.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.db.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.db.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.db.support_returning()
    }
}

/// A trait to help working with database errors
pub trait DatabaseErrors {
    /// return `true` if the error is a duplicate key error
    fn is_duplicate(&self) -> bool;
}

impl DatabaseErrors for DbErr {
    fn is_duplicate(&self) -> bool {
        match self {
            DbErr::Query(RuntimeErr::SqlxError(sqlx::error::Error::Database(err))) => {
                err.kind() == ErrorKind::UniqueViolation
            }
            _ => false,
        }
    }
}
