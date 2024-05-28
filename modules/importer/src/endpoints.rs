use super::service::{Error, ImporterService};
use crate::model::ImporterConfiguration;
use actix_web::{
    delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    post, put, web, HttpResponse, Responder,
};
use std::sync::Arc;
use trustify_auth::authenticator::Authenticator;
use trustify_common::{
    db::Database,
    model::{Paginated, Revisioned},
};
use trustify_infrastructure::app::new_auth;
use utoipa::OpenApi;

/// mount the "importer" module
pub fn configure(svc: &mut web::ServiceConfig, db: Database, auth: Option<Arc<Authenticator>>) {
    svc.app_data(web::Data::new(ImporterService::new(db)));
    svc.service(
        web::scope("/api/v1/importer")
            .wrap(new_auth(auth))
            .service(list)
            .service(create)
            .service(read)
            .service(update)
            .service(delete)
            .service(get_reports),
    );
}

#[derive(OpenApi)]
#[openapi(
    paths(list, create, read, update, delete, get_reports),
    components(schemas(
        crate::model::CommonImporter,
        crate::model::CsafImporter,
        crate::model::Importer,
        crate::model::ImporterConfiguration,
        crate::model::ImporterData,
        crate::model::ImporterReport,
        crate::model::PaginatedImporterReport,
        crate::model::RevisionedImporter,
        crate::model::SbomImporter,
        crate::model::State,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    responses(
        (status = 200, description = "List importer configurations", body = [Importer])
    )
)]
#[get("")]
/// List importer configurations
async fn list(service: web::Data<ImporterService>) -> Result<impl Responder, Error> {
    Ok(web::Json(service.list().await?))
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    request_body = ImporterConfiguration,
    params(
        ("name", Path, description = "The name of the importer"),
    ),
    responses(
        (status = 201, description = "Created a new importer configuration"),
        (status = 409, description = "An importer with that name already exists")
    )
)]
#[post("/{name}")]
/// Create a new importer configuration
async fn create(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Json(configuration): web::Json<ImporterConfiguration>,
) -> Result<impl Responder, Error> {
    service.create(name.into_inner(), configuration).await?;
    Ok(HttpResponse::Created().finish())
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    params(
        ("name", Path, description = "The name of the importer"),
    ),
    responses(
        (status = 200, description = "Retrieved importer configuration",
            body = Importer,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 404, description = "An importer with that name could not be found")
    )
)]
#[get("/{name}")]
/// Get an importer configuration
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

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    request_body = ImporterConfiguration,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match", Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Created a new importer configuration"),
        (status = 409, description = "An importer with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/{name}")]
/// Update an existing importer configuration
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

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match", Header, description = "The revision to delete"),
    ),
    responses(
        (status = 201, description = "Delete the importer configuration"),
    )
)]
#[delete("/{name}")]
/// Delete an importer configuration
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

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    responses(
        (status = 200, description = "Retrieved importer reports", body = PaginatedImporterReport),
    )
)]
#[get("/{name}/report")]
/// Get reports for an importer
async fn get_reports(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(service.get_reports(&name, paginated).await?))
}
