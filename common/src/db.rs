use anyhow::Context;
use migration::{async_trait::async_trait, Migrator, MigratorTrait};
use postgresql_embedded::PostgreSQL;
use sea_orm::{
    prelude::async_trait, ConnectOptions, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, ExecResult, QueryResult, RuntimeErr, Statement,
};
use sqlx::error::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tempfile::TempDir;

pub enum Transactional {
    None,
    Some(DatabaseTransaction),
}

impl Transactional {
    pub async fn commit(self) -> Result<(), DbErr> {
        match self {
            Transactional::None => {}
            Transactional::Some(inner) => {
                inner.commit().await?;
            }
        }

        Ok(())
    }
}

impl AsRef<Transactional> for Transactional {
    fn as_ref(&self) -> &Transactional {
        self
    }
}

impl AsRef<Transactional> for () {
    fn as_ref(&self) -> &Transactional {
        &Transactional::None
    }
}

/*
impl<'db> From<&'db DatabaseTransaction> for Transactional<'db> {
    fn from(inner: &'db DatabaseTransaction) -> Self {
        Self::Some(inner)
    }
}

 */

#[derive(Clone)]
pub enum ConnectionOrTransaction<'db> {
    Connection(&'db DatabaseConnection),
    Transaction(&'db DatabaseTransaction),
}

#[async_trait::async_trait]
impl ConnectionTrait for ConnectionOrTransaction<'_> {
    fn get_database_backend(&self) -> DbBackend {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.get_database_backend(),
            ConnectionOrTransaction::Transaction(inner) => inner.get_database_backend(),
        }
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.execute(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.execute(stmt).await,
        }
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.execute_unprepared(sql).await,
            ConnectionOrTransaction::Transaction(inner) => inner.execute_unprepared(sql).await,
        }
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.query_one(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.query_one(stmt).await,
        }
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.query_all(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.query_all(stmt).await,
        }
    }
}

#[derive(Debug)]
enum DbStrategy {
    External,
    Managed(Arc<(PostgreSQL, TempDir)>),
}

#[derive(Clone, Debug)]
pub struct Database {
    pub db: DatabaseConnection,
    db_strategy: Arc<DbStrategy>,
}

impl Database {
    async fn new(
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

        let db = sea_orm::Database::connect(opt).await?;

        log::debug!("applying migrations");
        Migrator::refresh(&db).await?;
        log::debug!("applied migrations");

        Ok(Self {
            db,
            db_strategy: Arc::new(db_strategy),
        })
    }

    pub async fn with_external_config(
        database: &crate::config::Database,
        bootstrap: bool,
    ) -> Result<Self, anyhow::Error> {
        if bootstrap {
            log::warn!("Bootstrapping database");
            Self::bootstrap(
                &database.username,
                &database.password,
                &database.host,
                database.port,
                &database.name,
                DbStrategy::External,
            )
            .await
        } else {
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
    }

    pub async fn for_test(name: &str) -> Result<Self, anyhow::Error> {
        use postgresql_embedded::Settings;

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

    async fn bootstrap(
        username: &str,
        password: &str,
        host: &str,
        port: impl Into<Option<u16>> + Copy,
        db_name: &str,
        db_strategy: DbStrategy,
    ) -> Result<Self, anyhow::Error> {
        let url = format!(
            "postgres://{}:{}@{}:{}/postgres",
            username,
            password,
            host,
            port.into().unwrap_or(5432)
        );
        log::debug!("bootstrap to {}", url);
        let db = sea_orm::Database::connect(url).await?;

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

#[async_trait]
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

    #[cfg(feature = "mock")]
    fn is_mock_connection(&self) -> bool {
        self.db.is_mock_connection()
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
