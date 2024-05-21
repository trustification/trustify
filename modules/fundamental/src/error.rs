use actix_http::StatusCode;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use sea_orm::DbErr;
use trustify_common::error::ErrorInformation;
use trustify_common::purl::PurlErr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(anyhow::Error),
    #[error(transparent)]
    Query(#[from] trustify_common::db::query::Error),
    #[error(transparent)]
    Ingestor(#[from] trustify_module_ingestor::service::Error),
    #[error(transparent)]
    Purl(#[from] PurlErr),
    #[error(transparent)]
    Actix(#[from] actix_web::Error),
    #[error("Invalid request {msg}")]
    BadRequest { msg: String, status: StatusCode },
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("Unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error(transparent)]
    Storage(anyhow::Error),
}

unsafe impl Send for Error {}

unsafe impl Sync for Error {}

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
            Self::Actix(err) => {
                HttpResponse::InternalServerError().json(ErrorInformation::new("System Actix", err))
            }
            Self::BadRequest { msg, status } => {
                HttpResponse::build(*status).json(ErrorInformation::new("Bad request", msg))
            }
            Self::Any(err) => HttpResponse::InternalServerError()
                .json(ErrorInformation::new("System unknown", err)),
            Error::Ingestor(inner) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Ingestor error", inner))
            }
            Error::UnsupportedHashAlgorithm => HttpResponse::InternalServerError()
                .json(ErrorInformation::new("Unsupported hash algorithm", "")),
            Error::Storage(inner) => HttpResponse::InternalServerError()
                .json(ErrorInformation::new("Unsupported hash algorithm", inner)),
            Error::Database(err) => HttpResponse::InternalServerError()
                .json(ErrorInformation::new("Database error", err)),
            Error::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Query error", err))
            }
        }
    }
}
