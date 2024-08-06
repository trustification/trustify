use crate::db::Database;
use anyhow::Context;
use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use tracing::{info_span, Instrument};

/// Create a new, embedded database instance
pub async fn create() -> anyhow::Result<(Database, PostgreSQL)> {
    let version = VersionReq::parse("=16.3.0").context("valid psql version")?;
    let settings = Settings {
        version,
        username: "postgres".to_string(),
        password: "trustify".to_string(),
        temporary: true,
        ..Default::default()
    };

    let postgresql = async {
        let mut postgresql = PostgreSQL::new(settings);
        postgresql
            .setup()
            .await
            .context("Setting up the test database")?;
        postgresql
            .start()
            .await
            .context("Starting the test database")?;
        Ok::<_, anyhow::Error>(postgresql)
    }
    .instrument(info_span!("start database"))
    .await?;

    let config = crate::config::Database {
        username: "postgres".into(),
        password: "trustify".into(),
        host: "localhost".into(),
        name: "test".into(),
        port: postgresql.settings().port,
        min_conn: 25,
        max_conn: 75,
    };
    let db = Database::bootstrap(&config)
        .await
        .context("Bootstrapping the test database")?;

    Ok((db, postgresql))
}
