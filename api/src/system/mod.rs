use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::sync::Arc;
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbErr, Statement,
    TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use crate::db::{ConnectionOrTransaction, Transactional};
use migration::Migrator;

pub mod error;
pub mod package;
pub mod sbom;
pub mod vulnerability;
pub mod scanner;

pub mod advisory;

pub mod cve;

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
    pub async fn new(
        username: &str,
        password: &str,
        host: &str,
        db_name: &str,
    ) -> Result<Self, anyhow::Error> {
        let url = format!("postgres://{}:{}@{}/{}", username, password, host, db_name);
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
        Self::bootstrap("postgres", "eggs", "localhost", name).await
    }

    pub async fn bootstrap(
        username: &str,
        password: &str,
        host: &str,
        db_name: &str,
    ) -> Result<Arc<Self>, anyhow::Error> {
        let url = format!("postgres://{}:{}@{}/postgres", username, password, host);
        println!("bootstrap to {}", url);
        let db = Database::connect(url).await?;

        let drop_db_result = db
            .execute(Statement::from_string(
                db.get_database_backend(),
                format!("DROP DATABASE IF EXISTS \"{}\";", db_name),
            ))
            .await?;

        println!("{:?}", drop_db_result);

        let create_db_result = db
            .execute(Statement::from_string(
                db.get_database_backend(),
                format!("CREATE DATABASE \"{}\";", db_name),
            ))
            .await?;

        println!("{:?}", create_db_result);

        db.close().await?;

        Ok(Arc::new(Self::new(username, password, host, db_name).await?))
    }

    pub async fn close(self) -> anyhow::Result<()> {
        Ok(self.db.close().await?)
    }
}
