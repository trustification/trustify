use crate::{
    license::{
        endpoints::spdx::{get_spdx_license, list_spdx_licenses},
        model::LicenseSummary,
        service::LicenseService,
    },
    Error,
};
use actix_web::{get, web, HttpResponse, Responder};
use std::str::FromStr;
use trustify_common::{
    db::{query::Query, Database},
    id::IdError,
    model::{Paginated, PaginatedResults},
};
use uuid::Uuid;

pub mod spdx;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let license_service = LicenseService::new(db);

    config
        .app_data(web::Data::new(license_service))
        .service(list_spdx_licenses)
        .service(get_spdx_license)
        .service(list_licenses)
        .service(get_license)
        .service(get_license_purls);
}

#[utoipa::path(
    tag = "license",
    operation_id = "listLicenses",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching licenses", body = PaginatedResults<LicenseSummary>),
    ),
)]
#[get("/v1/license")]
/// List licenses
pub async fn list_licenses(
    state: web::Data<LicenseService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.list_licenses(search, paginated).await?))
}

#[utoipa::path(
    tag = "license",
    operation_id = "getLicenses",
    responses(
        (status = 200, description = "The license", body = LicenseSummary),
    ),
)]
#[get("/v1/license/{uuid}")]
/// Retrieve license details
pub async fn get_license(
    state: web::Data<LicenseService>,
    uuid: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.get_license(*uuid).await?))
}

#[utoipa::path(
    tag = "license",
    operation_id = "getLicensePurls",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "The versioned pURLs allowing the license", body = LicenseSummary),
    ),
)]
#[get("/v1/license/{uuid}/purl")]
/// Retrieve pURLs covered by a license
pub async fn get_license_purls(
    state: web::Data<LicenseService>,
    uuid: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    let uuid = Uuid::from_str(&uuid).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
    Ok(HttpResponse::Ok().json(state.get_license_purls(uuid, search, paginated).await?))
}

#[cfg(test)]
mod test;
