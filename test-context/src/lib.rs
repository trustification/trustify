#![allow(clippy::expect_used)]

pub mod app;
pub mod auth;
pub mod call;
pub mod flame;
pub mod spdx;
pub mod subset;

use futures::Stream;
use peak_alloc::PeakAlloc;
use postgresql_embedded::PostgreSQL;
use serde::Serialize;
use std::{
    env,
    io::{Read, Seek},
    path::{Path, PathBuf},
};
use test_context::AsyncTestContext;
use tokio_util::{bytes::Bytes, io::ReaderStream};
use tracing::instrument;
use trustify_common::{self as common, db, decompress::decompress_async, hashing::Digests};
use trustify_module_ingestor::{
    graph::Graph,
    model::IngestResult,
    service::{Format, IngestorService},
};
use trustify_module_storage::service::fs::FileSystemBackend;

#[allow(dead_code)]
pub struct TrustifyContext {
    pub db: db::Database,
    pub graph: Graph,
    pub storage: FileSystemBackend,
    pub ingestor: IngestorService,
    pub mem_limit_mb: f32,
    postgresql: Option<PostgreSQL>,
}

#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;

impl TrustifyContext {
    async fn new(db: db::Database, postgresql: impl Into<Option<PostgreSQL>>) -> Self {
        let (storage, _) = FileSystemBackend::for_test()
            .await
            .expect("initializing the storage backend");
        let graph = Graph::new(db.clone());
        let ingestor = IngestorService::new(graph.clone(), storage.clone(), Default::default());
        let mem_limit_mb = env::var("MEM_LIMIT_MB")
            .unwrap_or("500".into())
            .parse()
            .expect("a numerical value");

        Self {
            db,
            graph,
            storage,
            ingestor,
            mem_limit_mb,
            postgresql: postgresql.into(),
        }
    }

    /// The paths are relative to `<workspace>/etc/test-data`.
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

    /// Same as [`Self::ingest_document_as`], but with a format of [`Format::Unknown`].
    ///
    /// The path is relative to `<workspace>/etc/test-data`.
    pub async fn ingest_document(&self, path: &str) -> Result<IngestResult, anyhow::Error> {
        self.ingest_document_as(path, Format::Unknown).await
    }

    /// Ingest a document with a specific format.
    ///
    /// The path is relative to `<workspace>/etc/test-data`.
    pub async fn ingest_document_as(
        &self,
        path: &str,
        format: Format,
    ) -> Result<IngestResult, anyhow::Error> {
        let bytes = document_bytes(path).await?;
        Ok(self
            .ingestor
            .ingest(&bytes, format, ("source", "TrustifyContext"), None)
            .await?)
    }

    pub async fn ingest_read<R: Read>(&self, mut read: R) -> Result<IngestResult, anyhow::Error> {
        let mut bytes = Vec::new();
        read.read_to_end(&mut bytes)?;

        Ok(self
            .ingestor
            .ingest(&bytes, Format::Unknown, ("source", "TrustifyContext"), None)
            .await?)
    }

    /// Ingest a document by ingesting its JSON representation
    pub async fn ingest_json<S: Serialize>(&self, doc: S) -> Result<IngestResult, anyhow::Error> {
        let bytes = serde_json::to_vec(&doc)?;

        Ok(self
            .ingestor
            .ingest(&bytes, Format::Unknown, ("source", "TrustifyContext"), None)
            .await?)
    }

    pub fn absolute_path(&self, path: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
        absolute(path)
    }

    pub async fn ingest_parallel<const N: usize>(
        &self,
        paths: [&str; N],
    ) -> Result<[IngestResult; N], anyhow::Error> {
        let mut f = vec![];

        for path in paths {
            f.push(self.ingest_document(path));
        }

        let r = futures::future::try_join_all(f).await?;
        let r = r.try_into().expect("Unexpected number of results");

        Ok(r)
    }
}

impl AsyncTestContext for TrustifyContext {
    #[instrument]
    #[allow(clippy::expect_used)]
    async fn setup() -> TrustifyContext {
        if env::var("EXTERNAL_TEST_DB").is_ok() {
            log::warn!("Using external database from 'DB_*' env vars");
            let config = common::config::Database::from_env().expect("DB config from env");

            let db = if matches!(
                env::var("EXTERNAL_TEST_DB_BOOTSTRAP").as_deref(),
                Ok("1" | "true")
            ) {
                common::db::Database::bootstrap(&config).await
            } else {
                common::db::Database::new(&config).await
            }
            .expect("Configuring the database");

            return TrustifyContext::new(db, None).await;
        }

        let (db, postgresql) = db::embedded::create()
            .await
            .expect("Create an embedded database");

        TrustifyContext::new(db, postgresql).await
    }

    async fn teardown(self) {
        let peak_mem = PEAK_ALLOC.peak_usage_as_mb();
        let args: Vec<String> = env::args().collect();
        // Prints the error message when running the tests with threads=1
        if args.iter().any(|arg| arg == "--test-threads=1") && peak_mem > self.mem_limit_mb {
            log::error!("Too much RAM used: {peak_mem} MB");
        }
        PEAK_ALLOC.reset_peak_usage();
    }
}

/// return an absolute part, relative to `<workspace>/etc/test-data`.
fn absolute(path: impl AsRef<Path>) -> Result<PathBuf, anyhow::Error> {
    let workspace_root: PathBuf = env!("CARGO_WORKSPACE_ROOT").into();
    let test_data = workspace_root.join("etc/test-data");
    Ok(test_data.join(path))
}

/// Load a test document and decompress it, if necessary.
pub async fn document_bytes(path: &str) -> Result<Bytes, anyhow::Error> {
    let bytes = document_bytes_raw(path).await?;
    let bytes = decompress_async(bytes, None, 0).await??;
    Ok(bytes)
}

/// Load a test document as-is, no decompression.
///
/// The path is relative to `<workspace>/etc/test-data`.
pub async fn document_bytes_raw(path: &str) -> Result<Bytes, anyhow::Error> {
    let bytes = tokio::fs::read(absolute(path)?).await?;
    Ok(bytes.into())
}

/// Get a stream for a document from the test-data directory
pub async fn document_stream(
    path: &str,
) -> Result<impl Stream<Item = Result<Bytes, std::io::Error>>, anyhow::Error> {
    let file = tokio::fs::File::open(absolute(path)?).await?;
    Ok(ReaderStream::new(file))
}

/// Read a document from the test-data directory. Does not decompress.
pub fn document_read(path: &str) -> Result<impl Read + Seek, anyhow::Error> {
    Ok(std::fs::File::open(absolute(path)?)?)
}

/// Read a document and parse it as JSON.
pub async fn document<T>(path: &str) -> Result<(T, Digests), anyhow::Error>
where
    T: serde::de::DeserializeOwned + Send + 'static,
{
    let data = document_bytes(path).await?;
    let digests = Digests::digest(&data);
    let f = move || Ok::<_, anyhow::Error>(serde_json::from_slice::<T>(&data)?);

    Ok((tokio::task::spawn_blocking(f).await??, digests))
}

#[cfg(test)]
mod test {
    use super::*;
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

        assert!(ingestion_result.document_id.is_some());

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

    #[test(tokio::test)]
    async fn test_document_struct() {
        use hex::ToHex;
        use osv::schema::Vulnerability;

        let (osv, digests): (Vulnerability, _) =
            document("osv/RUSTSEC-2021-0079.json").await.unwrap();

        assert_eq!(osv.id, "RUSTSEC-2021-0079");
        assert_eq!(
            digests.sha256.encode_hex::<String>(),
            "d113c2bd1ad6c3ac00a3a8d3f89d3f38de935f8ede0d174a55afe9911960cf51"
        );
    }
}
