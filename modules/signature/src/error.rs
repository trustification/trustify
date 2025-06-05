use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::DbErr;
use std::fmt::{Debug, Display};
use trustify_common::{error::ErrorInformation, id::IdError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IdKey(#[from] IdError),
    #[error(transparent)]
    Database(anyhow::Error),
    #[error(transparent)]
    Query(#[from] trustify_common::db::query::Error),
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("trust anchor '{0}' already exists")]
    AlreadyExists(String),
    #[error("trust anchor '{0}' not found")]
    NotFound(String),
    #[error("mid air collision")]
    MidAirCollision,
    #[error("storage error: {0}")]
    Storage(anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        Self::Database(value.into())
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("QueryError", err))
            }
            Self::IdKey(err) => HttpResponse::BadRequest().json(ErrorInformation::new("Key", err)),
            Self::AlreadyExists(err) => {
                HttpResponse::Conflict().json(ErrorInformation::new("AlreadyExists", err))
            }
            Self::NotFound(err) => {
                HttpResponse::NotFound().json(ErrorInformation::new("NotFound", err))
            }
            Self::MidAirCollision => HttpResponse::PreconditionFailed()
                .json(ErrorInformation::new("MidAirCollision", self)),

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

#[derive(Debug, thiserror::Error)]
pub enum PatchError<T>
where
    T: Debug + Display,
{
    #[error("failed to apply changes")]
    Transform(T),
    #[error(transparent)]
    Common(Error),
}

impl<T> From<Error> for PatchError<T>
where
    T: Debug + Display,
{
    fn from(value: Error) -> Self {
        Self::Common(value)
    }
}

impl<T> ResponseError for PatchError<T>
where
    T: Debug + Display,
{
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            PatchError::Common(err) => err.error_response(),
            PatchError::Transform(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "PatchTransform".into(),
                message: err.to_string(),
                details: None,
            }),
        }
    }
}
