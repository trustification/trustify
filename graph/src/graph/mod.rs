use crate::db::{ConnectionOrTransaction, Transactional};
use anyhow::{anyhow, Context};
use log::debug;
use migration::Migrator;
use postgresql_embedded;
use postgresql_embedded::{PostgreSQL, Settings};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr, Statement,
    TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use tempfile::TempDir;

pub mod advisory;
pub mod error;
pub mod package;
pub mod sbom;

mod cpe22;
pub mod vulnerability;

#[derive(Debug)]
pub enum DbStrategy {
    External,
    Managed(Arc<(PostgreSQL, TempDir)>),
}

#[derive(Debug, Clone)]
pub struct Graph {
    db: DatabaseConnection,
    db_strategy: Arc<DbStrategy>,
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
    pub async fn new(
        username: &str,
        password: &str,
        host: &str,
        port: impl Into<Option<u16>>,
        db_name: &str,
        db_strategy: DbStrategy,
    ) -> Result<Self, anyhow::Error> {
        let port = port.into().unwrap_or(5432);
        let url = format!("postgres://{username}:{password}@{host}:{port}/{db_name}");
        log::info!("connect to {}", url);

        let mut opt = ConnectOptions::new(url);
        opt.min_connections(16);
        opt.sqlx_logging_level(log::LevelFilter::Trace);

        let db = Database::connect(opt).await?;

        debug!("applying migrations");
        Migrator::refresh(&db).await?;
        debug!("applied migrations");

        Ok(Self {
            db,
            db_strategy: Arc::new(db_strategy),
        })
    }

    pub async fn with_external_config(
        database: &trustify_common::config::Database,
    ) -> Result<Self, anyhow::Error> {
        Self::new(
            &database.username,
            &database.password,
            &database.host,
            database.port,
            &database.name,
            DbStrategy::External,
        )
        .await
    }

    #[cfg(test)]
    pub async fn for_test(name: &str) -> Result<Self, anyhow::Error> {
        let tempdir = tempfile::tempdir()?;
        let installation_dir = tempdir.path().to_path_buf();
        let settings = Settings {
            username: "postgres".to_string(),
            password: "trustify".to_string(),
            temporary: true,
            installation_dir,
            ..Default::default()
        };

        let mut postgresql = PostgreSQL::new(PostgreSQL::default_version(), settings);
        postgresql.setup().await?;
        postgresql.start().await?;

        Self::bootstrap(
            "postgres",
            "trustify",
            "localhost",
            Some(postgresql.settings().port),
            name,
            DbStrategy::Managed(Arc::new((postgresql, tempdir))),
        )
        .await
    }

    pub(crate) fn connection<'db>(
        &'db self,
        tx: Transactional<'db>,
    ) -> ConnectionOrTransaction<'db> {
        match tx {
            Transactional::None => ConnectionOrTransaction::Connection(&self.db),
            Transactional::Some(tx) => ConnectionOrTransaction::Transaction(tx),
        }
    }

    pub async fn bootstrap(
        username: &str,
        password: &str,
        host: &str,
        port: impl Into<Option<u16>> + Copy,
        db_name: &str,
        db_strategy: DbStrategy,
    ) -> Result<Graph, anyhow::Error> {
        let url = format!(
            "postgres://{}:{}@{}:{}/postgres",
            username,
            password,
            host,
            port.into().unwrap_or(5432)
        );
        log::info!("bootstrap to {}", url);
        log::debug!("bootstrap to {}", url);
        let db = Database::connect(url).await?;

        let drop_db_result = db
            .execute(Statement::from_string(
                db.get_database_backend(),
                format!("DROP DATABASE IF EXISTS \"{}\";", db_name),
            ))
            .await?;

        let create_db_result = db
            .execute(Statement::from_string(
                db.get_database_backend(),
                format!("CREATE DATABASE \"{}\";", db_name),
            ))
            .await?;

        db.close().await?;

        Self::new(username, password, host, port, db_name, db_strategy).await
    }

    pub async fn close(self) -> anyhow::Result<()> {
        Ok(self.db.close().await?)
    }

    /// Ping the database.
    ///
    /// Intended to be used for health checks.
    pub async fn ping(&self) -> anyhow::Result<()> {
        self.db
            .ping()
            .await
            .context("failed to ping the database")?;
        Ok(())
    }
}
