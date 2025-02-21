use crate::license::{
    endpoints::spdx::{get_spdx_license, list_spdx_licenses},
    service::LicenseService,
};
use actix_web::web;

pub mod spdx;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    let license_service = LicenseService::new();

    config
        .app_data(web::Data::new(license_service))
        .service(list_spdx_licenses)
        .service(get_spdx_license);
}

#[cfg(test)]
mod test;
