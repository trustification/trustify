use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;

#[utoipa::path(
    tag = "package",
    context_path= "/api",
    params(
        ("uuid" = String, Path, description = "opaque UUID identifier for a package version")
    ),
    responses(
        (status = 200, description = "Details for the version of a package", body = PackageVersionDetails),
    ),
)]
#[get("/v1/package/version/{uuid}")]
pub async fn get(
    service: web::Data<PackageService>,
    uuid: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.package_version_by_uuid(&uuid, ()).await?))
}
