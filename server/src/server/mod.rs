use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use trustify_common::error::ErrorInformation;
use trustify_common::purl::PurlErr;
use trustify_graph::graph;

pub mod read;
pub mod write;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    System(graph::error::Error),
    #[error(transparent)]
    Purl(#[from] PurlErr),
    #[error(transparent)]
    Actix(#[from] actix_web::Error),
    #[error("Invalid request {msg}")]
    BadRequest { msg: String, status: StatusCode },
    #[error(transparent)]
    Any(#[from] anyhow::Error),
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
            Self::Actix(err) => {
                HttpResponse::InternalServerError().json(ErrorInformation::new("System Actix", err))
            }
            Self::BadRequest { msg, status } => {
                HttpResponse::build(*status).json(ErrorInformation::new("Bad request", msg))
            }
            Self::Any(err) => HttpResponse::InternalServerError()
                .json(ErrorInformation::new("System unknown", err)),
        }
    }
}
