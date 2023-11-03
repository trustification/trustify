use actix_web::ResponseError;
use huevos_api::system;
use std::fmt::Debug;

pub mod read;
pub mod write;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    System(system::error::Error),
}

impl From<system::error::Error> for Error {
    fn from(inner: system::error::Error) -> Self {
        Self::System(inner)
    }
}

impl ResponseError for Error {}
