use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use huevos_api::system;
use std::borrow::Cow;
use std::fmt::{Debug, Display};

pub mod read;
pub mod write;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    System(system::error::Error),
    #[error(transparent)]
    Purl(#[from] packageurl::Error),
}

impl From<system::error::Error> for Error {
    fn from(inner: system::error::Error) -> Self {
        Self::System(inner)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ErrorInformation {
    pub r#type: Cow<'static, str>,
    pub message: String,
}

impl ErrorInformation {
    pub fn new(r#type: impl Into<Cow<'static, str>>, message: impl Display) -> Self {
        Self {
            r#type: r#type.into(),
            message: message.to_string(),
        }
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
