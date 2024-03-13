use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use trustify_graph::graph;
use trustify_common::error::ErrorInformation;

pub mod importer;
pub mod read;
pub mod write;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    System(graph::error::Error),
    #[error(transparent)]
    Purl(#[from] packageurl::Error),
}

impl From<graph::error::Error> for Error {
    fn from(inner: graph::error::Error) -> Self {
        Self::System(inner)
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::System(err) => {
                HttpResponse::InternalServerError().json(ErrorInformation::new("System", err))
            }
            Self::Purl(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidPurlSyntax", err))
            }
        }
    }
}
