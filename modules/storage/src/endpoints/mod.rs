mod advisory;
mod sbom;

use crate::service::dispatch::DispatchBackend;
use actix_web::{body::BoxBody, web, HttpResponse, ResponseError};
use trustify_common::error::ErrorInformation;
use utoipa::OpenApi;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[source] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Storage(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Storage".into(),
                message: err.to_string(),
                details: None,
            }),
        }
    }
}

/// Mount the ingestor module
pub fn configure(config: &mut web::ServiceConfig, storage: impl Into<DispatchBackend>) {
    config
        .app_data(web::Data::new(storage.into()))
        .service(advisory::download_advisory)
        .service(sbom::download_sbom);
}

#[derive(OpenApi)]
#[openapi(
    paths(advisory::download_advisory, sbom::download_sbom,),
    components(),
    tags()
)]
pub struct ApiDoc;
