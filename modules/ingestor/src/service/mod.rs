pub mod advisory;
pub mod sbom;

mod format;
pub use format::Format;
use tokio::task::JoinError;
use tokio_util::io::ReaderStream;

use crate::{graph::Graph, model::IngestResult};
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use anyhow::anyhow;
use parking_lot::Mutex;
use sbom_walker::report::ReportSink;
use sea_orm::error::DbErr;
use std::sync::Arc;
use std::{fmt::Debug, time::Instant};
use tracing::instrument;
use trustify_common::{error::ErrorInformation, id::IdError};
use trustify_entity::labels::Labels;
use trustify_module_storage::service::{dispatch::DispatchBackend, StorageBackend};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    HashKey(#[from] IdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yml::Error),
    #[error(transparent)]
    Graph(#[from] crate::graph::error::Error),
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("storage error: {0}")]
    Storage(#[source] anyhow::Error),
    #[error(transparent)]
    Generic(anyhow::Error),
    #[error("Invalid format: {0}")]
    UnsupportedFormat(String),
    #[error("failed to await the task: {0}")]
    Join(#[from] JoinError),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Io(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "Io".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Json(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Yaml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "YamlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Storage(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Storage".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Join(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Join".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Db(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Database".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Graph(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Graph".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Generic(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Generic".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::UnsupportedFormat(fmt) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "UnsupportedFormat".into(),
                message: format!("Unsupported advisory format: {fmt}"),
                details: None,
            }),
            Error::HashKey(inner) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "Digest key error".into(),
                message: inner.to_string(),
                details: None,
            }),
        }
    }
}

#[derive(Clone)]
pub struct IngestorService {
    graph: Graph,
    storage: DispatchBackend,
}

impl IngestorService {
    pub fn new(graph: Graph, storage: impl Into<DispatchBackend>) -> Self {
        Self {
            graph,
            storage: storage.into(),
        }
    }

    pub fn storage(&self) -> &DispatchBackend {
        &self.storage
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    #[instrument(skip(self, bytes), err)]
    pub async fn ingest(
        &self,
        labels: impl Into<Labels> + Debug,
        issuer: Option<String>,
        bytes: &[u8],
    ) -> Result<IngestResult, Error> {
        let start = Instant::now();
        let fmt = Format::from_bytes(bytes)?;
        let stream = ReaderStream::new(bytes);

        let result = self
            .storage
            .store(stream)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;

        let stream = self
            .storage
            .retrieve(result.key())
            .await
            .map_err(Error::Storage)?
            .ok_or_else(|| Error::Storage(anyhow!("file went missing during upload")))?;

        let result = fmt
            .load(&self.graph, labels.into(), issuer, &result.digests, stream)
            .await?;

        let duration = Instant::now() - start;
        log::info!(
            "Ingested: {} ({}): took {}",
            result.id,
            result.document_id,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }
}

/// Capture warnings from the import process
#[derive(Default)]
pub(crate) struct Warnings(Arc<Mutex<Vec<String>>>);

impl Warnings {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReportSink for Warnings {
    fn error(&self, msg: String) {
        self.0.lock().push(msg);
    }
}

impl From<Warnings> for Vec<String> {
    fn from(value: Warnings) -> Self {
        match Arc::try_unwrap(value.0) {
            Ok(warnings) => warnings.into_inner(),
            Err(warnings) => warnings.lock().clone(),
        }
    }
}

pub struct Discard;

impl ReportSink for Discard {
    fn error(&self, _msg: String) {}
}
