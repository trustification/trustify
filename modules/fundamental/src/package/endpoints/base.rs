use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;

#[utoipa::path(
    tag = "package",
    params(
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/package/base/{uuid}")]
pub async fn get(
    service: web::Data<PackageService>,
    uuid: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.package_by_uuid(&uuid, ()).await?))
}
