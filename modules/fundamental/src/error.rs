use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use langchain_rust::{agent::AgentError, chain::ChainError};
use sea_orm::DbErr;
use trustify_common::{decompress, error::ErrorInformation, id::IdError, purl::PurlErr};
use trustify_module_storage::service::StorageKeyError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IdKey(#[from] IdError),
    #[error(transparent)]
    StorageKey(#[from] StorageKeyError),
    #[error(transparent)]
    Database(anyhow::Error),
    #[error(transparent)]
    Query(#[from] trustify_common::db::query::Error),
    #[error(transparent)]
    Ingestor(#[from] trustify_module_ingestor::service::Error),
    #[error(transparent)]
    Purl(#[from] PurlErr),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("Unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error(transparent)]
    Storage(anyhow::Error),
    #[error("Invalid data model {0}")]
    Data(String),
    #[error("Internal Server Error: {0}")]
    Internal(String),
    #[error(transparent)]
    Compression(#[from] decompress::Error),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error(transparent)]
    AgentError(AgentError),
    #[error(transparent)]
    ChainError(ChainError),
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        Self::Database(value.into())
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Purl(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidPurlSyntax", err))
            }
            Self::BadRequest(msg) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Bad request", msg))
            }
            Self::NotFound(msg) => {
                HttpResponse::NotFound().json(ErrorInformation::new("Not Found", msg))
            }
            Self::Ingestor(inner) => inner.error_response(),
            Self::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Query error", err))
            }
            Self::IdKey(err) => HttpResponse::BadRequest().json(ErrorInformation::new("Key", err)),
            Self::StorageKey(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Storage Key", err))
            }
            Self::Compression(decompress::Error::UnknownType) => {
                HttpResponse::UnsupportedMediaType()
                    .json(ErrorInformation::new("UnsupportedCompression", self))
            }
            Self::Compression(decompress::Error::PayloadTooLarge) => {
                HttpResponse::PayloadTooLarge().json(ErrorInformation::new("PayloadTooLarge", self))
            }
            Self::Compression(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("CompressionError", err))
            }

            // All other cases are internal system errors that are not expected to occur.
            // They are logged and a generic error response is returned to avoid leaking
            // internal state to end users.
            err => {
                log::error!("{err}");
                HttpResponse::InternalServerError()
                    .json(ErrorInformation::new("Internal Server Error", ""))
            }
        }
    }
}
