#[cfg(test)]
mod test;

use crate::product::service::ProductService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;
use uuid::Uuid;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let service = ProductService::new(db);
    config
        .app_data(web::Data::new(service))
        .service(all)
        .service(get);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, get),
    components(schemas(
        crate::product::model::ProductHead,
        crate::product::model::ProductSummary,
        crate::product::model::PaginatedProductSummary,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "product",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching products", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/v1/product")]
pub async fn all(
    state: web::Data<ProductService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_products(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "product",
    context_path = "/api",
    params(
        ("id", Path, description = "Opaque ID of the product")
    ),
    responses(
        (status = 200, description = "Matching product", body = ProductHead),
        (status = 404, description = "Matching product not found"),
    ),
)]
#[get("/v1/product/{id}")]
pub async fn get(
    state: web::Data<ProductService>,
    id: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    let fetched = state.fetch_product(*id, ()).await?;
    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
