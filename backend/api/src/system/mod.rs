use crate::db::{ConnectionOrTransaction, Transactional};
use migration::Migrator;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbErr, Statement, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::sync::Arc;

pub mod advisory;
pub mod error;
pub mod package;
pub mod sbom;

mod cpe22;
pub mod vulnerability;

const DB_URL: &str = "postgres://postgres:eggs@localhost";
const DB_NAME: &str = "huevos";

pub type System = Arc<InnerSystem>;

#[derive(Clone)]
pub struct InnerSystem {
    db: DatabaseConnection,
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

impl InnerSystem {
    pub async fn with_config(
        database: &trustify_common::config::Database,
    ) -> Result<Self, anyhow::Error> {
        Self::new(
            &database.username,
            &database.password,
            &database.host,
            database.port,
            &database.name,
        )
        .await
    }

    pub async fn new(
        username: &str,
        password: &str,
        host: &str,
        port: impl Into<Option<u16>>,
        db_name: &str,
    ) -> Result<Self, anyhow::Error> {
        let port = port.into().unwrap_or(5432);
        let url = format!("postgres://{username}:{password}@{host}:{port}/{db_name}");
        println!("connect to {}", url);
        let db = Database::connect(url).await?;

        Migrator::refresh(&db).await?;

        Ok(Self { db })
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

    #[cfg(test)]
    pub async fn for_test(name: &str) -> Result<Arc<Self>, anyhow::Error> {
        Self::bootstrap("postgres", "eggs", "localhost", None, name)
            .await
            .map(Arc::new)
    }

    pub async fn bootstrap(
        username: &str,
        password: &str,
        host: &str,
        port: impl Into<Option<u16>>,
        db_name: &str,
    ) -> Result<Self, anyhow::Error> {
        let url = format!("postgres://{}:{}@{}/postgres", username, password, host);
        println!("bootstrap to {}", url);
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

        Self::new(username, password, host, port, db_name).await
    }

    pub async fn close(self) -> anyhow::Result<()> {
        Ok(self.db.close().await?)
    }
}
