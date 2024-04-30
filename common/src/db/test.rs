use crate::config::Database;
use clap::{ArgMatches, FromArgMatches, Parser};
use postgresql_embedded::{PostgreSQL, Settings};
use std::env;
use tempfile::TempDir;
use test_context::{test_context, AsyncTestContext};
use tracing::{info_span, instrument, Instrument};

pub struct TrustifyContext {
    pub db: crate::db::Database,
    postgresql: Option<PostgreSQL>,
    tempdir: Option<TempDir>,
}

/// collect database information for the external test database.
///
/// **NOTE:** This may panic in case where the [`Database`] arguments cannot be parsed.
#[allow(clippy::expect_used)]
fn external_test_db() -> Database {
    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        database: Database,
    }

    Cli::try_parse_from(Vec::<String>::new())
        .expect("Unable to extract test database arguments")
        .database
}

impl AsyncTestContext for TrustifyContext {
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::expect_used)]
    #[instrument]
    async fn setup() -> TrustifyContext {
        if env::var("EXTERNAL_TEST_DB").is_ok() {
            let config = external_test_db();
            log::warn!("Using external database from 'DB_*' env vars: {config:#?}");
            let db = crate::db::Database::new(&config)
                .await
                .expect("failed connecting to the external test database");
            db.migrate()
                .await
                .expect("failed to run database migration");
            return TrustifyContext {
                db,
                postgresql: None,
                tempdir: None,
            };
        }

        let tempdir = tempfile::tempdir().unwrap();
        let installation_dir = tempdir.path().to_path_buf();
        let settings = Settings {
            username: "postgres".to_string(),
            password: "trustify".to_string(),
            temporary: true,
            installation_dir,
            ..Default::default()
        };

        let mut postgresql = async {
            let mut postgresql = PostgreSQL::new(PostgreSQL::default_version(), settings);
            postgresql.setup().await.unwrap();
            postgresql.start().await.unwrap();
            postgresql
        }
        .instrument(info_span!("start database"))
        .await;

        let config = crate::config::Database {
            username: "postgres".into(),
            password: "trustify".into(),
            host: "localhost".into(),
            name: "test".into(),
            port: postgresql.settings().port,
        };
        let db = crate::db::Database::bootstrap(&config).await.unwrap();

        TrustifyContext {
            db,
            postgresql: Some(postgresql),
            tempdir: Some(tempdir),
        }
    }

    async fn teardown(self) {
        // Perform any teardown you wish.
    }
}
