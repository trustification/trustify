pub mod embedded;

use anyhow::ensure;
use migration::Migrator;
use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::MigratorTrait;
use tracing::instrument;
use trustify_common::{config, db};

pub struct Database<'a>(pub &'a db::Database);

impl<'a> Database<'a> {
    #[instrument(skip(self), err)]
    pub async fn migrate(&self) -> Result<(), anyhow::Error> {
        log::debug!("applying migrations");
        Migrator::up(self.0, None).await?;
        log::debug!("applied migrations");

        Ok(())
    }

    #[instrument(skip(self), err)]
    pub async fn refresh(&self) -> Result<(), anyhow::Error> {
        log::warn!("refreshing database schema...");
        Migrator::refresh(self.0).await?;
        log::warn!("refreshing database schema... done!");

        Ok(())
    }

    #[instrument(err)]
    pub async fn bootstrap(database: &config::Database) -> Result<db::Database, anyhow::Error> {
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

        let db = db::Database::new(database).await?;
        db.execute_unprepared("CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\";")
            .await?;
        Database(&db).migrate().await?;

        Ok(db)
    }
}
