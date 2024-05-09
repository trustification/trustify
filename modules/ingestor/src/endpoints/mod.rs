mod advisory;
mod sbom;

use crate::graph::Graph;
use crate::service::IngestorService;
use actix_web::web;
use bytesize::ByteSize;
use trustify_common::db::Database;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::OpenApi;

/// Mount the ingestor module
pub fn configure(
    config: &mut web::ServiceConfig,
    db: Database,
    storage: impl Into<DispatchBackend>,
) {
    let service = IngestorService::new(Graph::new(db), storage);
    let limit = ByteSize::gb(1).as_u64() as usize;
    config
        .app_data(web::Data::new(service))
        .app_data(web::PayloadConfig::default().limit(limit))
        .service(advisory::upload_advisory)
        .service(sbom::upload_sbom);
}

#[derive(OpenApi)]
#[openapi(
    paths(advisory::upload_advisory, sbom::upload_sbom,),
    components(),
    tags()
)]
pub struct ApiDoc;
