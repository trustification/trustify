use std::env;

use postgresql_archive::Version;
use postgresql_embedded::{PostgreSQL, Settings};
use std::str::FromStr;
use tempfile::TempDir;
use test_context::{test_context, AsyncTestContext};
use tracing::{info_span, instrument, Instrument};

pub struct TrustifyContext {
    pub db: crate::db::Database,
    postgresql: Option<PostgreSQL>,
    tempdir: Option<TempDir>,
}

impl AsyncTestContext for TrustifyContext {
    #[instrument]
    #[allow(clippy::expect_used)]
    async fn setup() -> TrustifyContext {
        if env::var("EXTERNAL_TEST_DB").is_ok() {
            log::warn!("Using external database from 'DB_*' env vars");
            let config = crate::config::Database::from_env().expect("DB config from env");

            let db = if env::var("EXTERNAL_TEST_DB_BOOTSTRAP").is_ok() {
                crate::db::Database::bootstrap(&config).await
            } else {
                crate::db::Database::new(&config).await
            }
            .expect("Configuring the database");

            return TrustifyContext {
                db,
                postgresql: None,
                tempdir: None,
            };
        }

        let tempdir = tempfile::tempdir().expect("Creating the test database tmp directory");
        let installation_dir = tempdir.path().to_path_buf();
        let settings = Settings {
            username: "postgres".to_string(),
            password: "trustify".to_string(),
            temporary: true,
            installation_dir,
            ..Default::default()
        };

        let mut postgresql = async {
            let version = Version::from_str("16.3.0").expect("valid psql version");
            let mut postgresql = PostgreSQL::new(version, settings);
            postgresql
                .setup()
                .await
                .expect("Setting up the test database");
            postgresql
                .start()
                .await
                .expect("Starting the test database");
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
        let db = crate::db::Database::bootstrap(&config)
            .await
            .expect("Bootstrapping the test database");

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
