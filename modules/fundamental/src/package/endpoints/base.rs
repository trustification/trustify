use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;

#[utoipa::path(
    context_path= "/api/v1/package",
    tag = "package",
    params(
        ("uuid" = String, Path, description = "opaque UUID identifier for a base package")
    ),
    responses(
        (status = 200, description = "Details for the versionless base package", body = PackageDetails),
    ),
)]
#[get("/base/{uuid}")]
pub async fn get(
    service: web::Data<PackageService>,
    uuid: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.package_by_uuid(&uuid, ()).await?))
}
