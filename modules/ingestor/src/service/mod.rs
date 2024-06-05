pub mod advisory;
pub mod cve;
mod format;
pub mod hashing;
pub mod sbom;

use crate::graph::Graph;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use anyhow::anyhow;
use bytes::Bytes;
pub use format::Format;
use futures::Stream;
use sea_orm::error::DbErr;
use std::time::Instant;
use trustify_common::error::ErrorInformation;
use trustify_common::hash::{HashKey, HashKeyError};
use trustify_module_storage::service::dispatch::DispatchBackend;
use trustify_module_storage::service::{StorageBackend, SyncAdapter};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    HashKey(#[from] HashKeyError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Graph(#[from] crate::graph::error::Error),
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("storage error: {0}")]
    Storage(#[source] anyhow::Error),
    #[error(transparent)]
    Generic(anyhow::Error),
    #[error("Invalid advisory format: {0}")]
    UnsupportedFormat(String),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Json(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Storage(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Storage".into(),
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

    pub async fn ingest<S, E>(
        &self,
        source: &str,
        issuer: Option<String>,
        fmt: Format,
        stream: S,
    ) -> Result<String, Error>
    where
        E: std::error::Error,
        S: Stream<Item = Result<Bytes, E>>,
    {
        let start = Instant::now();

        let digest = self
            .storage
            .store(stream)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;
        let sha256 = hex::encode(digest);

        // TODO: can advisories have an algorithm prefix?
        let hash_key = HashKey::Sha256(sha256);

        let storage = SyncAdapter::new(self.storage.clone());
        let reader = storage
            .retrieve(hash_key)
            .await
            .map_err(Error::Storage)?
            .ok_or_else(|| Error::Storage(anyhow!("file went missing during upload")))?;

        // TODO: advisories return string but sbom's return UUID?
        let result = fmt.load(&self.graph, source, issuer, reader).await?;

        let duration = Instant::now() - start;
        log::info!(
            "Ingested: {} from {}: took {}",
            result,
            source,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }
}
