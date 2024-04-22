use sea_orm::DbErr;
use trustify_common::purl::PurlErr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Purl(#[from] PurlErr),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Database(#[from] DbErr),

    #[error(transparent)]
    Semver(#[from] lenient_semver::parser::OwnedError),

    #[error(transparent)]
    Search(#[from] trustify_module_search::service::Error),

    #[error(transparent)]
    Any(#[from] anyhow::Error),
}
