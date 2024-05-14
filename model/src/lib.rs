use sea_orm::DbErr;

pub mod advisory;
pub mod vulnerability;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(#[from] DbErr),

    #[error(transparent)]
    Any(#[from] anyhow::Error),
}
