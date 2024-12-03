use crate::sbom::service::SbomService;
use actix_web::{patch, put, web, HttpResponse, Responder};
use trustify_auth::{authorizer::Require, UpdateSbom};
use trustify_common::db::Database;
use trustify_common::id::Id;
use trustify_entity::labels::Labels;

/// Modify existing labels of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "patchSbomLabels",
    request_body = Labels,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Modified the labels of the SBOM"),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[patch("/v1/sbom/{id}/label")]
pub async fn update(
    sbom: web::Data<SbomService>,
    id: web::Path<Id>,
    web::Json(update): web::Json<Labels>,
    _: Require<UpdateSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(
        match sbom
            .update_labels(id.into_inner(), |labels| labels.apply(update))
            .await?
        {
            Some(()) => HttpResponse::NoContent(),
            None => HttpResponse::NotFound(),
        },
    )
}

/// Replace the labels of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "updateSbomLabels",
    request_body = Labels,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Replaced the labels of the SBOM"),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[put("/v1/sbom/{id}/label")]
pub async fn set(
    sbom: web::Data<SbomService>,
    db: web::Data<Database>,
    id: web::Path<Id>,
    web::Json(labels): web::Json<Labels>,
    _: Require<UpdateSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(
        match sbom
            .set_labels(id.into_inner(), labels, db.as_ref())
            .await?
        {
            Some(()) => HttpResponse::NoContent(),
            None => HttpResponse::NotFound(),
        },
    )
}
