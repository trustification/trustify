#[cfg(test)]
mod test;

use crate::{
    product::{
        model::{details::ProductDetails, summary::ProductSummary},
        service::ProductService,
    },
    Error,
};
use actix_web::{delete, get, web, HttpResponse, Responder};
use sea_orm::TransactionTrait;
use trustify_auth::{authorizer::Require, DeleteMetadata, ReadMetadata};
use trustify_common::{
    db::{query::Query, Database},
    model::{Paginated, PaginatedResults},
};
use uuid::Uuid;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = ProductService::new();
    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(all)
        .service(delete)
        .service(get);
}

#[utoipa::path(
    tag = "product",
    operation_id = "listProducts",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching products", body = PaginatedResults<ProductSummary>),
    ),
)]
#[get("/v1/product")]
pub async fn all(
    state: web::Data<ProductService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadMetadata>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_products(search, paginated, db.as_ref()).await?))
}

#[utoipa::path(
    tag = "product",
    operation_id = "getProduct",
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
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    _: Require<ReadMetadata>,
) -> actix_web::Result<impl Responder> {
    let fetched = state.fetch_product(*id, db.as_ref()).await?;
    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[utoipa::path(
    tag = "product",
    operation_id = "deleteProduct",
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
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    _: Require<DeleteMetadata>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;

    match state.fetch_product(*id, &tx).await? {
        Some(v) => {
            let rows_affected = state.delete_product(v.head.id, &tx).await?;
            match rows_affected {
                0 => Ok(HttpResponse::NotFound().finish()),
                1 => {
                    tx.commit().await?;
                    Ok(HttpResponse::Ok().json(v))
                }
                _ => Err(Error::Internal("Unexpected number of rows affected".into())),
            }
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}
