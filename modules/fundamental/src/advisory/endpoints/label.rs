use crate::advisory::service::AdvisoryService;
use actix_web::{HttpResponse, Responder, patch, put, web};
use trustify_auth::{UpdateAdvisory, authorizer::Require};
use trustify_common::{db::Database, id::Id};
use trustify_entity::labels::{Labels, Update};

/// Replace the labels of an advisory
#[utoipa::path(
    tag = "advisory",
    operation_id = "updateAdvisoryLabels",
    request_body = Labels,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Replaced the labels of the advisory"),
        (status = 404, description = "The advisory could not be found"),
    ),
)]
#[put("/v2/advisory/{id}/label")]
pub async fn set(
    advisory: web::Data<AdvisoryService>,
    db: web::Data<Database>,
    id: web::Path<Id>,
    web::Json(labels): web::Json<Labels>,
    _: Require<UpdateAdvisory>,
) -> actix_web::Result<impl Responder> {
    Ok(
        match advisory
            .set_labels(id.into_inner(), labels, db.as_ref())
            .await?
        {
            Some(()) => HttpResponse::NoContent(),
            None => HttpResponse::NotFound(),
        },
    )
}

/// Modify existing labels of an advisory
#[utoipa::path(
    tag = "advisory",
    operation_id = "patchAdvisoryLabels",
    request_body = Update,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Modified the labels of the advisory"),
        (status = 404, description = "The advisory could not be found"),
    ),
)]
#[patch("/v2/advisory/{id}/label")]
pub async fn update(
    advisory: web::Data<AdvisoryService>,
    id: web::Path<Id>,
    web::Json(update): web::Json<Update>,
    _: Require<UpdateAdvisory>,
) -> actix_web::Result<impl Responder> {
    Ok(
        match advisory
            .update_labels(id.into_inner(), |labels| update.apply_to(labels))
            .await?
        {
            Some(()) => HttpResponse::NoContent(),
            None => HttpResponse::NotFound(),
        },
    )
}
