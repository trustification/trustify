use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, ModelTrait, QueryFilter, Set, Statement,
};
use sea_orm_migration::MigratorTrait;

use crate::system::package::PackageSystem;
use migration::Migrator;
use crate::system::sbom::SbomSystem;

mod package;
mod sbom;

const DB_URL: &str = "postgres://postgres:eggs@localhost";
const DB_NAME: &str = "huevos";

pub struct System {
    db: Arc<DatabaseConnection>,
}

impl System {
    pub(crate) async fn start() -> Result<Self, anyhow::Error> {


        let db: DatabaseConnection = Database::connect(DB_URL).await?;

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("DROP DATABASE IF EXISTS \"{}\";", DB_NAME),
        ))
        .await?;

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("CREATE DATABASE \"{}\";", DB_NAME),
        ))
        .await?;

        Migrator::refresh(&db).await?;

        Ok(Self { db: Arc::new(db) })
    }

    pub fn package(&self) -> PackageSystem {
        PackageSystem {
            db: self.db.clone(),
        }
    }

    pub fn sbom(&self) -> SbomSystem {
        SbomSystem {
            db: self.db.clone()
        }

    }
}
