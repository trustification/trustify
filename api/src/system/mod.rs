use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::process::Output;
use std::str::FromStr;
use std::sync::Arc;

use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, Database, DatabaseConnection,
    DatabaseTransaction, DbErr, EntityTrait, ModelTrait, QueryFilter, Set, Statement,
    TransactionError, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;

use crate::system::package::PackageSystem;
use crate::system::sbom::SbomSystem;
use migration::Migrator;

mod error;
mod package;
mod sbom;
mod vex;

pub use vex::VexSystem;

const DB_URL: &str = "postgres://postgres:eggs@localhost";
const DB_NAME: &str = "huevos";

#[derive(Clone)]
pub struct System {
    db: Arc<DatabaseConnection>,
}

pub struct Context<'t> {
    tx: &'t DatabaseTransaction,
}

impl<'t> Context<'t> {
    pub fn vex(&self) -> VexSystem {
        VexSystem { tx: &self.tx }
    }
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

impl<E: Send> std::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transaction(_) => write!(f, "transaction error"),
            Self::Database(err) => write!(f, "database error: {err}"),
        }
    }
}

impl<E: Send> std::error::Error for Error<E> {}

impl System {
    pub async fn start() -> Result<Self, anyhow::Error> {
        let db = Database::connect(DB_URL).await?;
        Ok(Self { db: Arc::new(db) })
    }

    pub(crate) async fn bootstrap(&self) -> Result<(), anyhow::Error> {
        self.db
            .execute(Statement::from_string(
                self.db.get_database_backend(),
                format!("DROP DATABASE IF EXISTS \"{}\";", DB_NAME),
            ))
            .await?;

        self.db
            .execute(Statement::from_string(
                self.db.get_database_backend(),
                format!("CREATE DATABASE \"{}\";", DB_NAME),
            ))
            .await?;

        Migrator::refresh(self.db.as_ref()).await?;

        Ok(())
    }

    pub fn package(&self) -> PackageSystem {
        PackageSystem {
            db: self.db.clone(),
        }
    }

    pub fn sbom(&self) -> SbomSystem {
        SbomSystem {
            db: self.db.clone(),
        }
    }

    pub async fn transaction<F, T, E>(&self, f: F) -> Result<T, Error<E>>
    where
        F: for<'c> FnOnce(Context<'c>) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: Send,
    {
        let db = self.db.clone();
        let tx = db.begin().await?;

        let ctx = Context { tx: &tx };
        match f(ctx).await {
            Err(err) => {
                tx.rollback().await?;
                Err(Error::Transaction(err))
            }
            Ok(r) => {
                tx.commit().await?;
                Ok(r)
            }
        }
    }
}
