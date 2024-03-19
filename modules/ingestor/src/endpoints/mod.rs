mod advisory;

use actix_web::web;

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(advisory::upload_advisory);
}
