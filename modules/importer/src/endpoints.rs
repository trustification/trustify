use super::service::{Error, ImporterService};
use crate::model::Revisioned;
use actix_web::http::header;
use actix_web::{delete, get, post, put, web, HttpResponse, Responder};
use serde_json::Value;
use trustify_common::db::Database;

/// mount the "importer" module
pub fn configure(svc: &mut web::ServiceConfig, db: Database) {
    svc.app_data(web::Data::new(ImporterService::new(db)));
    svc.service(
        web::scope("/api/v1/importer")
            .service(list)
            .service(create)
            .service(read)
            .service(update)
            .service(delete),
    );
}

#[get("")]
async fn list(service: web::Data<ImporterService>) -> Result<impl Responder, Error> {
    Ok(web::Json(service.list().await?))
}

#[post("/{name}")]
async fn create(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Json(configuration): web::Json<Value>,
) -> Result<impl Responder, Error> {
    service.create(name.into_inner(), configuration).await?;
    Ok(HttpResponse::Created().finish())
}

#[get("/{name}")]
async fn read(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
) -> Result<Option<impl Responder>, Error> {
    Ok(service
        .read(&name)
        .await?
        .map(|Revisioned { value, revision }| {
            HttpResponse::Ok()
                .append_header((header::ETAG, revision))
                .json(value)
        }))
}

#[put("/{name}")]
async fn update(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    if_match: Option<web::Header<header::ETag>>,
    web::Json(configuration): web::Json<Value>,
) -> Result<impl Responder, Error> {
    service
        .update(
            name.into_inner(),
            configuration,
            if_match.map(|v| v.to_string()).as_deref(),
        )
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[delete("/{name}")]
async fn delete(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    if_match: Option<web::Header<header::ETag>>,
) -> Result<impl Responder, Error> {
    Ok(
        match service
            .delete(&name, if_match.map(|v| v.to_string()).as_deref())
            .await?
        {
            true => HttpResponse::NoContent().finish(),
            false => HttpResponse::NoContent().finish(),
        },
    )
}
