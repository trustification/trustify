use crate::sbom::service::SbomService;
use actix_web::{HttpResponse, Responder, get, patch, put, web};

use serde::Deserialize;
use trustify_auth::{
    Permission, UpdateSbom,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
};
use trustify_common::{db::Database, id::Id};
use trustify_entity::labels::{Labels, Update};
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
struct LabelQuery {
    #[serde(default)]
    filter_text: String,

    #[serde(default)]
    limit: u64,
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "listSbomLabels",
    params(
        LabelQuery,
    ),
    responses(
        (status = 200, description = "List all unique key/value labels from all SBOMs", body = Vec<Value>),
    ),
)]
#[get("/v2/sbom-labels")]
/// List all unique key/value labels from all SBOMs
pub async fn all(
    fetch: web::Data<SbomService>,
    db: web::Data<Database>,
    web::Query(query): web::Query<LabelQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch
        .fetch_labels(&query.filter_text, query.limit, db.as_ref())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Modify existing labels of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "patchSbomLabels",
    request_body = Update,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Modified the labels of the SBOM"),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[patch("/v2/sbom/{id}/label")]
pub async fn update(
    sbom: web::Data<SbomService>,
    id: web::Path<Id>,
    web::Json(update): web::Json<Update>,
    _: Require<UpdateSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(
        match sbom
            .update_labels(id.into_inner(), |labels| update.apply_to(labels))
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
#[put("/v2/sbom/{id}/label")]
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
