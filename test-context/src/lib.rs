#![allow(clippy::expect_used)]

use futures::{stream, Stream};
use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::env;
use std::env::current_dir;
use std::io::ErrorKind;
use std::path::PathBuf;
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

impl TrustifyContext {
    async fn new(db: common::db::Database, postgresql: impl Into<Option<PostgreSQL>>) -> Self {
        let (storage, _) = FileSystemBackend::for_test()
            .await
            .expect("initializing the storage backend");
        let graph = Graph::new(db.clone());

        let ingestor = IngestorService::new(graph.clone(), storage.clone());

        Self {
            db,
            graph,
            storage,
            ingestor,
            postgresql: postgresql.into(),
        }
    }

    pub async fn ingest_documents<'a, P: IntoIterator<Item = &'a str>>(
        &self,
        paths: P,
    ) -> Result<Vec<IngestResult>, anyhow::Error> {
        let mut results = Vec::new();
        for path in paths {
            results.push(self.ingest_document(path).await?);
        }
        Ok(results)
    }

    pub async fn ingest_document(&self, path: &str) -> Result<IngestResult, anyhow::Error> {
        let bytes = document_bytes(path).await?;
        let format = Format::from_bytes(&bytes)?;
        let stream = ReaderStream::new(bytes.as_ref());

        Ok(self.ingestor.ingest((), None, format, stream).await?)
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

            return TrustifyContext::new(db, None).await;
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

        TrustifyContext::new(db, postgresql).await
    }

    async fn teardown(self) {
        // Perform any teardown you wish.
    }
}

pub async fn document_bytes(path: &str) -> Result<Bytes, anyhow::Error> {
    let workspace_root = find_workspace_root()?;
    let test_data = workspace_root.join("etc").join("test-data");
    let path_buf = test_data.join(path);
    let mut file = tokio::fs::File::open(path_buf).await?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    if path.ends_with(".xz") {
        bytes = liblzma::decode_all(&*bytes)?;
    }
    Ok(Bytes::copy_from_slice(&bytes))
}

pub async fn document_stream(
    path: &str,
) -> Result<impl Stream<Item = Result<Bytes, std::io::Error>>, anyhow::Error> {
    let bytes = document_bytes(path).await?;
    Ok(stream::once(async { Ok(bytes) }))
}

#[cfg(test)]
mod test {
    use crate::{document_bytes, document_stream};

    use super::TrustifyContext;
    use futures::StreamExt;
    use test_context::test_context;
    use test_log::test;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_documents(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = ctx
            .ingest_documents(["zookeeper-3.9.2-cyclonedx.json"])
            .await?;

        let ingestion_result = &result[0];

        assert!(!ingestion_result.document_id.is_empty());

        Ok(())
    }

    #[test(tokio::test)]
    async fn test_document_bytes() {
        let bytes = document_bytes("zookeeper-3.9.2-cyclonedx.json")
            .await
            .unwrap();
        assert!(!bytes.is_empty());
    }

    #[test(tokio::test)]
    async fn test_document_stream() {
        let stream = document_stream("zookeeper-3.9.2-cyclonedx.json")
            .await
            .unwrap();
        assert!(Box::pin(stream).next().await.is_some());
    }
}
