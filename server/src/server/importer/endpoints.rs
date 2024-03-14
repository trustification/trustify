use crate::server::importer::{service::Error, ImporterService};
use actix_web::{delete, get, post, put, web, web::Json, HttpResponse, Responder};
use serde_json::Value;

#[get("")]
async fn list(service: web::Data<ImporterService>) -> Result<impl Responder, Error> {
    Ok(Json(service.list().await?))
}

#[post("/{name}")]
async fn create(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    Json(configuration): web::Json<Value>,
) -> Result<impl Responder, Error> {
    service.create(name.into_inner(), configuration).await?;
    Ok(HttpResponse::Created().finish())
}

#[get("/{name}")]
async fn read(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
) -> Result<Option<impl Responder>, Error> {
    Ok(service.read(&name).await?.map(Json))
}

#[put("/{name}")]
async fn update(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    Json(configuration): web::Json<Value>,
) -> Result<impl Responder, Error> {
    service.update(name.into_inner(), configuration).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[delete("/{name}")]
async fn delete(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
) -> Result<impl Responder, Error> {
    Ok(match service.delete(&name).await? {
        true => HttpResponse::NoContent().finish(),
        false => HttpResponse::NoContent().finish(),
    })
}
