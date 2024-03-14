mod endpoints;
mod model;
mod service;
mod test;

use crate::server::importer::service::ImporterService;
use actix_web::{delete, get, post, put, web, Responder};
use endpoints::*;
use trustify_graph::graph::Graph;

/// mount the "importer" module
pub fn configure(svc: &mut web::ServiceConfig, graph: Graph) {
    svc.app_data(web::Data::new(ImporterService::new(graph)));
    svc.service(
        web::scope("/api/v1/importer")
            .service(list)
            .service(create)
            .service(read)
            .service(update)
            .service(delete),
    );
}
