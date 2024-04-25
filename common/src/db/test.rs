use postgresql_embedded::{PostgreSQL, Settings};
use test_context::{test_context, AsyncTestContext};

pub struct TrustifyContext {
    pub db: crate::db::Database,
    postgresql: PostgreSQL,
}

impl AsyncTestContext for TrustifyContext {
    #[allow(clippy::unwrap_used)]
    async fn setup() -> TrustifyContext {
        let tempdir = tempfile::tempdir().unwrap();
        let installation_dir = tempdir.path().to_path_buf();
        let settings = Settings {
            username: "postgres".to_string(),
            password: "trustify".to_string(),
            temporary: true,
            installation_dir,
            ..Default::default()
        };

        let mut postgresql = PostgreSQL::new(PostgreSQL::default_version(), settings);
        postgresql.setup().await.unwrap();
        postgresql.start().await.unwrap();

        let config = crate::config::Database {
            username: "postgres".into(),
            password: "trustify".into(),
            host: "localhost".into(),
            name: "test".into(),
            port: postgresql.settings().port,
        };
        let db = crate::db::Database::bootstrap(&config).await.unwrap();

        TrustifyContext { db, postgresql }
    }

    async fn teardown(self) {
        // Perform any teardown you wish.
    }
}
