use super::service::{Error, ImporterService};
use crate::model::ImporterConfiguration;
use actix_web::{
    delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    post, put, web, HttpResponse, Responder,
};
use trustify_common::db::Database;
use trustify_common::model::{Paginated, Revisioned};

/// mount the "importer" module
pub fn configure(svc: &mut web::ServiceConfig, db: Database) {
    svc.app_data(web::Data::new(ImporterService::new(db)));
    svc.service(
        web::scope("/api/v1/importer")
            .service(list)
            .service(create)
            .service(read)
            .service(update)
            .service(delete)
            .service(get_reports),
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
    web::Json(configuration): web::Json<ImporterConfiguration>,
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
                .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
                .json(value)
        }))
}

#[put("/{name}")]
async fn update(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(configuration): web::Json<ImporterConfiguration>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .update_configuration(&name, revision, configuration)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[delete("/{name}")]
async fn delete(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    Ok(match service.delete(&name, revision).await? {
        true => HttpResponse::NoContent().finish(),
        false => HttpResponse::NoContent().finish(),
    })
}

#[get("/{name}/report")]
async fn get_reports(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(service.get_reports(&name, paginated).await?))
}
