mod advisory;

use actix_web::web;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(advisory::upload_advisory);
}

#[derive(OpenApi)]
#[openapi(paths(advisory::upload_advisory), components(), tags())]
pub struct ApiDoc;
