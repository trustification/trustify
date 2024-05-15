use actix_web::ResponseError;
use sea_orm::DbErr;

pub mod endpoints;

pub mod service;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(#[from] DbErr),

    #[error(transparent)]
    Search(#[from] trustify_common::db::query::Error),

    #[error(transparent)]
    Any(#[from] anyhow::Error),
}

impl From<trustify_model::Error> for Error {
    fn from(value: trustify_model::Error) -> Self {
        match value {
            trustify_model::Error::Database(inner) => Self::Database(inner),
            trustify_model::Error::Any(inner) => Self::Any(inner),
        }
    }
}

impl ResponseError for Error {}
