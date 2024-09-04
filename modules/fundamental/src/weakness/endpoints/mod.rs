use crate::weakness::service::WeaknessService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let weakness_service = WeaknessService::new(db);

    config
        .app_data(web::Data::new(weakness_service))
        .service(list_weaknesses)
        .service(get_weakness);
}

#[derive(OpenApi)]
#[openapi(
    paths(list_weaknesses, get_weakness,),
    components(schemas(
        crate::weakness::model::PaginatedWeaknessSummary,
        crate::weakness::model::WeaknessSummary,
        crate::weakness::model::WeaknessDetails,
        crate::weakness::model::WeaknessHead,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "weakness",
    operation_id = "listWeaknesses",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching weaknesses", body = PaginatedLicenseSummary),
    ),
)]
#[get("/v1/weakness")]
/// List weaknesses
pub async fn list_weaknesses(
    state: web::Data<WeaknessService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.list_weaknesses(search, paginated).await?))
}

#[utoipa::path(
    tag = "weakness",
    operation_id = "getWeakness",
    context_path = "/api",
    responses(
        (status = 200, description = "The weakness", body = LicenseSummary),
    ),
)]
#[get("/v1/weakness/{id}")]
/// Retrieve weakness details
pub async fn get_weakness(
    state: web::Data<WeaknessService>,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.get_weakness(&id).await?))
}

#[cfg(test)]
mod test;
