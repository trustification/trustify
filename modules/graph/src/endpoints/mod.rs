pub mod package;
pub mod vulnerability;

pub mod advisory;

use crate::graph;
use crate::graph::Graph;
use crate::model::advisory::AdvisorySummary;
use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{web, HttpResponse, ResponseError};
use std::sync::Arc;
use trustify_common::error::ErrorInformation;
use trustify_common::model::PaginatedResults;
use trustify_common::purl::PurlErr;
use trustify_entity::importer;
use utoipa::openapi::Schema;
use utoipa::{OpenApi, ToSchema};

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(
            web::scope("/api/v1/advisory")
                .service(advisory::all)
                .service(advisory::get),
        )
        .service(
            web::scope("/api/v1/package")
                .service(package::dependencies)
                .service(package::variants),
        )
        .service(
            web::scope("/api/v1/vulnerability")
                .service(vulnerability::all)
                .service(vulnerability::advisories)
                .service(vulnerability::affected_packages)
                .service(vulnerability::affected_products),
        );
}

#[derive(OpenApi)]
#[openapi(
    paths(
        package::dependencies,
        package::variants,
        advisory::all,
        advisory::get,
        vulnerability::all,
        vulnerability::advisories,
        vulnerability::affected_packages,
        vulnerability::affected_products
    ),
    components(schemas(
        crate::model::advisory::AdvisoryDetails,
        crate::model::advisory::AdvisoryVulnerability,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
    )),
    tags()
)]
pub struct ApiDoc;

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
