mod advisory;
mod sbom;

use crate::service::IngestorService;
use actix_web::web;
use trustify_common::db::Database;
use trustify_module_graph::graph::Graph;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::OpenApi;

/// Mount the ingestor module
pub fn configure(
    config: &mut web::ServiceConfig,
    db: Database,
    storage: impl Into<DispatchBackend>,
) {
    let service = IngestorService::new(Graph::new(db), storage);
    config
        .app_data(web::Data::new(service))
        .service(advisory::upload_advisory)
        .service(advisory::download_advisory)
        .service(sbom::upload_sbom)
        .service(sbom::download_sbom);
}

#[derive(OpenApi)]
#[openapi(
    paths(
        advisory::download_advisory,
        advisory::upload_advisory,
        sbom::download_sbom,
        sbom::upload_sbom,
    ),
    components(),
    tags()
)]
pub struct ApiDoc;
