use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::env;
use std::env::current_dir;
use std::io::ErrorKind;
use std::path::PathBuf;
use test_context::AsyncTestContext;
use tokio_util::io::ReaderStream;
use tracing::{info_span, instrument, Instrument};
use trustify_common as common;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;

#[allow(dead_code)]
pub struct TrustifyContext {
    pub db: common::db::Database,
    pub graph: Graph,
    pub storage: FileSystemBackend,
    pub ingestor: IngestorService,
    postgresql: Option<PostgreSQL>,
}

impl TrustifyContext {
    pub async fn ingest_documents<'a, P: IntoIterator<Item = (Format, &'a str)>>(
        &self,
        paths: P,
    ) -> Result<(), anyhow::Error> {
        let workspace_root = find_workspace_root()?;
        let test_data = workspace_root.join("etc").join("test-data");

        for (format, path) in paths {
            //ingestor.ingest((), None, Format::from_bytes(bytes), bytes)
            let path = test_data.join(path);
            let file = tokio::fs::File::open(path).await?;
            let stream = ReaderStream::new(file);

            self.ingestor.ingest((), None, format, stream).await?;
        }
        Ok(())
    }
}

fn find_workspace_root() -> Result<PathBuf, anyhow::Error> {
    let current_dir = current_dir()?;

    let mut i = Some(current_dir.as_path());

    while let Some(cur) = i {
        if cur.join("rust-toolchain.toml").exists() {
            return Ok(cur.to_path_buf());
        }
        i = cur.parent();
    }

    Err(std::io::Error::new(ErrorKind::NotFound, "damnit").into())
}

impl AsyncTestContext for TrustifyContext {
    #[instrument]
    #[allow(clippy::expect_used)]
    async fn setup() -> TrustifyContext {
        if env::var("EXTERNAL_TEST_DB").is_ok() {
            log::warn!("Using external database from 'DB_*' env vars");
            let config = common::config::Database::from_env().expect("DB config from env");

            let db = if env::var("EXTERNAL_TEST_DB_BOOTSTRAP").is_ok() {
                common::db::Database::bootstrap(&config).await
            } else {
                common::db::Database::new(&config).await
            }
            .expect("Configuring the database");

            let (storage, _) = FileSystemBackend::for_test()
                .await
                .expect("initializing the storage backend");
            let graph = Graph::new(db.clone());

            let ingestor = IngestorService::new(graph.clone(), storage.clone());

            return TrustifyContext {
                db,
                storage,
                graph,
                ingestor,
                postgresql: None,
            };
        }

        let version = VersionReq::parse("=16.3.0").expect("valid psql version");
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
                .expect("Setting up the test database");
            postgresql
                .start()
                .await
                .expect("Starting the test database");
            postgresql
        }
        .instrument(info_span!("start database"))
        .await;

        let config = common::config::Database {
            username: "postgres".into(),
            password: "trustify".into(),
            host: "localhost".into(),
            name: "test".into(),
            port: postgresql.settings().port,
        };
        let db = common::db::Database::bootstrap(&config)
            .await
            .expect("Bootstrapping the test database");

        let (storage, _) = FileSystemBackend::for_test()
            .await
            .expect("initializing the storage backend");
        let graph = Graph::new(db.clone());

        let ingestor = IngestorService::new(graph.clone(), storage.clone());

        TrustifyContext {
            db,
            storage,
            graph,
            ingestor,
            postgresql: Some(postgresql),
        }
    }

    async fn teardown(self) {
        // Perform any teardown you wish.
    }
}
