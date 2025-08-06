use anyhow::Context;
use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::path::Path;
use tracing::{Instrument, info_span};
use trustify_common::db::Database;

/// Create common default settings for the embedded database
fn default_settings() -> anyhow::Result<Settings> {
    // **NOTE:** Changing the default version here, one should also change the env-var in the CI job
    let version = VersionReq::parse(option_env!("POSTGRESQL_VERSION").unwrap_or("=17.2.0"))
        .context("valid psql version")?;
    Ok(Settings {
        version,
        username: "postgres".to_string(),
        password: "trustify".to_string(),
        temporary: true,
        ..Default::default()
    })
}

/// Create a new, embedded database instance
pub async fn create() -> anyhow::Result<(Database, PostgreSQL)> {
    create_for(default_settings()?).await
}

/// Create a new, embedded database instance in a specific directory
pub async fn create_in(base: impl AsRef<Path>) -> anyhow::Result<(Database, PostgreSQL)> {
    let base = base.as_ref();

    create_for(Settings {
        data_dir: base.join("data"),
        installation_dir: base.join("instance"),
        ..default_settings()?
    })
    .await
}

/// Create a new, embedded database instance, using the provided settings
async fn create_for(settings: Settings) -> anyhow::Result<(Database, PostgreSQL)> {
    log::info!("creating embedded database - version: {}", settings.version);

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
        ..crate::config::Database::from_env()?
    };
    let db = super::Database::bootstrap(&config)
        .await
        .context("Bootstrapping the test database")?;

    Ok((db, postgresql))
}
