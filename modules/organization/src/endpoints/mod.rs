use crate::service::OrganizationService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let service = OrganizationService::new(db);
    config
        .app_data(web::Data::new(service))
        .service(web::scope("/api/v1/organization").service(all).service(get));
}

#[derive(OpenApi)]
#[openapi(
    paths(all, get),
    components(schemas(
        trustify_model::organization::OrganizationHead,
        trustify_model::organization::OrganizationSummary,
        trustify_model::organization::OrganizationDetails,
        trustify_model::organization::PaginatedOrganizationSummary,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "organization",
    context_path = "/api/v1/organization",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching organizations", body = PaginatedAdvisorySummary),
    ),
)]
#[get("")]
pub async fn all(
    state: web::Data<OrganizationService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_organizations(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "organization",
    context_path = "/api/v1/organization",
    params(
        ("id", Path, description = "Opaque ID of the organization")
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "Matching advisory not found"),
    ),
)]
#[get("/{id}")]
pub async fn get(
    state: web::Data<OrganizationService>,
    id: web::Path<i32>,
) -> actix_web::Result<impl Responder> {
    println!("HEY");
    let fetched = state.fetch_organization(*id, ()).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[cfg(test)]
mod test;
