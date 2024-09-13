use actix_http::StatusCode;
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
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
    #[error("Invalid request {msg}")]
    BadRequest { msg: String, status: StatusCode },
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
            Self::BadRequest { msg, status } => {
                HttpResponse::build(*status).json(ErrorInformation::new("Bad request", msg))
            }
            Error::Ingestor(inner) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Ingestor error", inner))
            }
            Error::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Query error", err))
            }
            Error::IdKey(err) => HttpResponse::BadRequest().json(ErrorInformation::new("Key", err)),
            Error::StorageKey(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Storage Key", err))
            }
            Error::Compression(decompress::Error::UnknownType) => {
                HttpResponse::UnsupportedMediaType()
                    .json(ErrorInformation::new("UnsupportedCompression", self))
            }
            Error::Compression(err) => {
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
