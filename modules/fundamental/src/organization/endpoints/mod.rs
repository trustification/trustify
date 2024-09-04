#[cfg(test)]
mod test;

use crate::organization::service::OrganizationService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;
use uuid::Uuid;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let service = OrganizationService::new(db);
    config
        .app_data(web::Data::new(service))
        .service(all)
        .service(get);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, get),
    components(schemas(
        crate::organization::model::OrganizationHead,
        crate::organization::model::OrganizationSummary,
        crate::organization::model::OrganizationDetails,
        crate::organization::model::PaginatedOrganizationSummary,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "organization",
    operation_id = "listOrganizations",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching organizations", body = PaginatedOrganizationSummary),
    ),
)]
#[get("/v1/organization")]
/// List organizations
pub async fn all(
    state: web::Data<OrganizationService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_organizations(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "organization",
    operation_id = "getOrganization",
    context_path = "/api",
    params(
        ("id", Path, description = "Opaque ID of the organization")
    ),
    responses(
        (status = 200, description = "Matching organization", body = OrganizationDetails),
        (status = 404, description = "Matching organization not found"),
    ),
)]
#[get("/v1/organization/{id}")]
/// Retrieve organization details
pub async fn get(
    state: web::Data<OrganizationService>,
    id: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    let fetched = state.fetch_organization(*id, ()).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
