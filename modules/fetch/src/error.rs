use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use sea_orm::DbErr;
use trustify_common::error::ErrorInformation;
use trustify_common::purl::PurlErr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(#[from] DbErr),

    #[error(transparent)]
    Search(#[from] trustify_common::db::query::Error),

    #[error(transparent)]
    Any(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Database(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Database".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Any(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Any".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Search(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Any".into(),
                message: err.to_string(),
                details: None,
            }),
        }
    }
}
