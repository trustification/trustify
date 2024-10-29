#[cfg(test)]
mod test;

use crate::{
    product::{
        model::{details::ProductDetails, summary::PaginatedProductSummary},
        service::ProductService,
    },
    Error::Internal,
};
use actix_web::{delete, get, web, HttpResponse, Responder};
use trustify_common::{db::query::Query, db::Database, model::Paginated};
use utoipa::OpenApi;
use uuid::Uuid;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let service = ProductService::new(db);
    config
        .app_data(web::Data::new(service))
        .service(all)
        .service(delete)
        .service(get);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, delete, get),
    components(schemas(
        crate::product::model::ProductHead,
        crate::product::model::ProductVersionHead,
        crate::product::model::details::ProductVersionDetails,
        crate::product::model::details::ProductSbomHead,
        crate::product::model::summary::ProductSummary,
        crate::product::model::summary::PaginatedProductSummary,
        crate::product::model::details::ProductDetails,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "product",
    operation_id = "listProducts",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching products", body = PaginatedProductSummary),
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
    operation_id = "getProduct",
    context_path = "/api",
    params(
        ("id", Path, description = "Opaque ID of the product")
    ),
    responses(
        (status = 200, description = "Matching product", body = ProductDetails),
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

#[utoipa::path(
    tag = "product",
    operation_id = "deleteProduct",
    context_path = "/api",
    params(
        ("id", Path, description = "Opaque ID of the product")
    ),
    responses(
        (status = 200, description = "Matching product", body = ProductDetails),
        (status = 404, description = "Matching product not found"),
    ),
)]
#[delete("/v1/product/{id}")]
pub async fn delete(
    state: web::Data<ProductService>,
    id: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    match state.fetch_product(*id, ()).await? {
        Some(v) => {
            let rows_affected = state.delete_product(v.head.id, ()).await?;
            match rows_affected {
                0 => Ok(HttpResponse::NotFound().finish()),
                1 => Ok(HttpResponse::Ok().json(v)),
                _ => Err(Internal("Unexpected number of rows affected".into()).into()),
            }
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}
