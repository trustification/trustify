pub mod advisory;
pub mod dataset;
pub mod sbom;
pub mod weakness;

mod format;
pub use format::Format;

use crate::service::dataset::{DatasetIngestResult, DatasetLoader};
use crate::{graph::Graph, model::IngestResult};
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use anyhow::anyhow;
use parking_lot::Mutex;
use sbom_walker::report::ReportSink;
use sea_orm::error::DbErr;
use std::sync::Arc;
use std::{fmt::Debug, time::Instant};
use tokio::task::JoinError;
use tokio_util::io::ReaderStream;
use tracing::instrument;
use trustify_common::{error::ErrorInformation, id::IdError};
use trustify_entity::labels::Labels;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::{dispatch::DispatchBackend, StorageBackend};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    HashKey(#[from] IdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    JsonPath(#[from] jsonpath_rust::parser::JsonPathParserError),
    #[error(transparent)]
    Xml(#[from] roxmltree::Error),
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
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error("payload too large")]
    PayloadTooLarge,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Json(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::JsonPath(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonPath".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Yaml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "YamlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Xml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "XmlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Io(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "I/O".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Utf8(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "UTF-8".into(),
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
            Self::Zip(inner) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "ZipError".into(),
                message: inner.to_string(),
                details: None,
            }),
            Self::PayloadTooLarge => HttpResponse::PayloadTooLarge().json(ErrorInformation {
                error: "PayloadTooLarge".into(),
                message: self.to_string(),
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

    pub fn db(&self) -> trustify_common::db::Database {
        self.graph.db.clone()
    }

    #[instrument(skip(self, bytes), err)]
    pub async fn ingest(
        &self,
        bytes: &[u8],
        format: Format,
        labels: impl Into<Labels> + Debug,
        issuer: Option<String>,
    ) -> Result<IngestResult, Error> {
        let start = Instant::now();

        // We want to resolve the format first to avoid storing a
        // document that we can't subsequently retrieve and load into
        // the database.
        let fmt = match format {
            Format::Advisory => Format::advisory_from_bytes(bytes)?,
            Format::SBOM => Format::sbom_from_bytes(bytes)?,
            Format::Unknown => Format::from_bytes(bytes)?,
            v => v,
        };
        let stream = ReaderStream::new(bytes);

        let result = self
            .storage
            .store(stream)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;

        let result = fmt
            .load(&self.graph, labels.into(), issuer, &result.digests, bytes)
            .await?;

        match fmt {
            Format::SPDX | Format::CycloneDX => {
                let analysis_service = AnalysisService::new(self.graph.db.clone());
                if result.id.to_string().starts_with("urn:uuid:") {
                    match analysis_service // TODO: today we chop off 'urn:uuid:' prefix using .split_off on result.id
                        .load_graphs(vec![result.id.to_string().split_off("urn:uuid:".len())], ())
                        .await
                    {
                        Ok(_) => log::debug!(
                        "Analysis graph for sbom: {} loaded successfully.",
                        result.id.value()
                    ),
                        Err(e) => log::warn!(
                        "Error loading sbom {} into analysis graph : {}",
                        result.id.value(),
                        e
                    ),
                    }
                }
            }
            _ => {}
        };

        let duration = Instant::now() - start;
        log::debug!(
            "Ingested: {} ({}): took {}",
            result.id,
            result.document_id,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }

    /// Ingest a dataset archive
    #[instrument(skip(self, bytes), ret, err)]
    pub async fn ingest_dataset(
        &self,
        bytes: &[u8],
        labels: impl Into<Labels> + Debug,
        limit: usize,
    ) -> Result<DatasetIngestResult, Error> {
        let loader = DatasetLoader::new(self.graph(), self.storage(), limit);
        loader.load(labels.into(), bytes).await
    }
}

/// Capture warnings from the import process
#[derive(Default)]
pub(crate) struct Warnings(Arc<Mutex<Vec<String>>>);

impl Warnings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, msg: String) {
        self.0.lock().push(msg);
    }
}

impl ReportSink for Warnings {
    fn error(&self, msg: String) {
        self.add(msg)
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
