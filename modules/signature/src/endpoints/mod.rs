mod test;

use crate::{
    error::{Error, PatchError},
    model::{TrustAnchor, TrustAnchorData},
    service::{SignatureService, TrustAnchorService},
};
use actix_web::{
    HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    patch, post, put, web,
};
use std::convert::Infallible;
use trustify_auth::{
    CreateTrustAnchor, DeleteTrustAnchor, ReadTrustAnchor, UpdateTrustAnchor, authorizer::Require,
};
use trustify_common::{
    db::Database,
    endpoints::guards,
    model::{Paginated, PaginatedResults, Revisioned},
};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let signature_service = SignatureService::new();
    let trust_anchor_service = TrustAnchorService::new(db);

    config
        .app_data(web::Data::new(signature_service))
        .app_data(web::Data::new(trust_anchor_service))
        .service(list)
        .service(create)
        .service(read)
        .service(update)
        .service(patch_json_merge)
        .service(delete)
        .service(set_enabled);
}

#[utoipa::path(
    tag = "trustAnchor",
    operation_id = "listTrustAnchors",
    responses(
        (status = 200, description = "List trust anchors", body = [PaginatedResults<TrustAnchor>])
    )
)]
#[get("/v2/trust-anchor")]
/// List trust anchors
async fn list(
    service: web::Data<TrustAnchorService>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadTrustAnchor>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(service.list(paginated).await?))
}

#[utoipa::path(
    tag = "trustAnchors",
    operation_id = "createTrustAnchors",
    request_body = TrustAnchor,
    params(
        ("id", Path, description = "The ID of the trust anchor to create"),
    ),
    responses(
        (status = 201, description = "Created a new trust anchor"),
        (status = 409, description = "A trust anchor with this name already exists"),
    )
)]
#[post("/v2/trust-anchor/{id}")]
/// Create a new trust anchor configuration
async fn create(
    service: web::Data<TrustAnchorService>,
    id: web::Path<String>,
    web::Json(data): web::Json<TrustAnchorData>,
    _: Require<CreateTrustAnchor>,
) -> Result<impl Responder, Error> {
    service.create(id.into_inner(), data).await?;
    Ok(HttpResponse::Created().finish())
}

#[utoipa::path(
    tag = "trustAnchor",
    operation_id = "getTrustAnchor",
    params(
        ("id", Path, description = "The name of the trust anchor"),
    ),
    responses(
        (status = 200, description = "Retrieved trust anchor configuration",
            body = Revisioned<TrustAnchor>,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 404, description = "A trust anchor with that name could not be found")
    )
)]
#[get("/v2/trust-anchor/{id}")]
/// Get a trust anchor configuration
async fn read(
    service: web::Data<TrustAnchorService>,
    name: web::Path<String>,
    _: Require<ReadTrustAnchor>,
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
    tag = "trustAnchor",
    operation_id = "updateTrustAnchor",
    request_body = TrustAnchor,
    params(
        ("id", Path, description = "The ID of the trust anchor"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the trust anchor"),
        (status = 409, description = "A trust anchor with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/v2/trust-anchor/{id}")]
/// Update an existing trust anchor configuration
async fn update(
    service: web::Data<TrustAnchorService>,
    id: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(data): web::Json<TrustAnchorData>,
    _: Require<UpdateTrustAnchor>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service.update_data(&id, revision, data).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "trustAnchor",
    operation_id = "patchTrustAnchor",
    request_body(
        content = serde_json::Value,
        content_type = guards::JSON_MERGE_CONTENT_TYPE,
    ),
    params(
        ("id", Path, description = "The name of the trust anchor"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Created a new trust anchor configuration"),
        (status = 409, description = "A trust anchor with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[patch("/v2/trust-anchor/{id}", guard = "guards::json_merge")]
/// Update an existing trust anchor
async fn patch_json_merge(
    service: web::Data<TrustAnchorService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(patch): web::Json<serde_json::Value>,
    _: Require<UpdateTrustAnchor>,
) -> Result<impl Responder, PatchError<serde_json::Error>> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .patch_data(&name, revision, |config| {
            let mut json = serde_json::to_value(&config)?;
            json_merge_patch::json_merge_patch(&mut json, &patch);
            serde_json::from_value(json)
        })
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "trustAnchor",
    operation_id = "deleteTrustAnchor",
    params(
        ("id", Path, description = "The name of the trust anchor"),
        ("if-match"=Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 201, description = "Delete the trust anchor"),
    )
)]
#[delete("/v2/trust-anchor/{id}")]
/// Delete a trust anchor
async fn delete(
    service: web::Data<TrustAnchorService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<DeleteTrustAnchor>,
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
    tag = "trustAnchor",
    operation_id = "enableTrustAnchor",
    request_body = bool,
    params(
        ("id", Path, description = "The name of the trust anchor"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the active state"),
        (status = 404, description = "A trust anchor with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/v2/trust-anchor/{id}/enabled")]
/// Set the active state of a trust anchor
async fn set_enabled(
    service: web::Data<TrustAnchorService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(state): web::Json<bool>,
    _: Require<UpdateTrustAnchor>,
) -> Result<impl Responder, PatchError<Infallible>> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .patch_data(&name, revision, |mut trust_anchor| {
            trust_anchor.disabled = !state;
            Ok(trust_anchor)
        })
        .await?;

    Ok(HttpResponse::NoContent().finish())
}
