use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::collections::HashMap;
use std::env;
use std::env::current_dir;
use std::io::ErrorKind;
use std::ops::Index;
use std::path::{Path, PathBuf};
use test_context::AsyncTestContext;
use tokio::io::AsyncReadExt;
use tokio_util::bytes::Bytes;
use tokio_util::io::ReaderStream;
use tracing::{info_span, instrument, Instrument};
use trustify_common as common;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::model::IngestResult;
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

pub struct IngestionResults {
    results: HashMap<String, Result<IngestResult, anyhow::Error>>,
}

impl Index<&str> for IngestionResults {
    type Output = Result<IngestResult, anyhow::Error>;

    fn index(&self, index: &str) -> &Self::Output {
        self.results.get(index).expect("valid document path")
    }
}

impl TrustifyContext {
    pub async fn ingest_documents<'a, P: IntoIterator<Item = &'a str>>(
        &self,
        paths: P,
    ) -> Result<IngestionResults, anyhow::Error> {
        let workspace_root = find_workspace_root()?;
        let test_data = workspace_root.join("etc").join("test-data");

        let mut results = HashMap::new();

        for path in paths {
            results.insert(
                path.to_string(),
                self.ingest_document_inner(&test_data, path).await,
            );
        }

        Ok(IngestionResults { results })
    }

    pub async fn ingest_document(&self, path: &str) -> Result<IngestResult, anyhow::Error> {
        let workspace_root = find_workspace_root()?;
        let test_data = workspace_root.join("etc").join("test-data");

        self.ingest_document_inner(&test_data, path).await
    }

    async fn ingest_document_inner(
        &self,
        test_data: &Path,
        path: &str,
    ) -> Result<IngestResult, anyhow::Error> {
        let path_buf = test_data.join(path);
        let mut file = tokio::fs::File::open(path_buf).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;

        if path.ends_with(".xz") {
            bytes = lzma::decompress(&bytes)?;
        }

        let format = Format::from_bytes(&bytes)?;
        let stream = ReaderStream::new(bytes.as_ref());

        self.ingestor
            .ingest((), None, format, stream)
            .await
            .map_err(|e| e.into())
    }

    pub async fn document_bytes(&self, path: &str) -> Result<Bytes, anyhow::Error> {
        let workspace_root = find_workspace_root()?;
        let test_data = workspace_root.join("etc").join("test-data");
        self.document_bytes_inner(&test_data, path).await
    }

    async fn document_bytes_inner(
        &self,
        test_data: &Path,
        path: &str,
    ) -> Result<Bytes, anyhow::Error> {
        let path_buf = test_data.join(path);
        let mut file = tokio::fs::File::open(path_buf).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;

        Ok(Bytes::copy_from_slice(&bytes))
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

#[cfg(test)]
mod test {
    use super::TrustifyContext;
    use test_context::test_context;
    use test_log::test;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_documents(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = ctx
            .ingest_documents(["zookeeper-3.9.2-cyclonedx.json"])
            .await?;

        let ingestion_result = &result["zookeeper-3.9.2-cyclonedx.json"];

        assert!(ingestion_result.is_ok());

        Ok(())
    }
}
