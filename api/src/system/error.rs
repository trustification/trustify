use huevos_common::purl::PurlErr;
use sea_orm::DbErr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Purl(#[from] PurlErr),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Database(#[from] DbErr),

    #[error(transparent)]
    Any(#[from] anyhow::Error),
}
