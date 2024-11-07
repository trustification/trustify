#[cfg(test)]
mod test;

use crate::organization::{
    model::{OrganizationDetails, OrganizationSummary},
    service::OrganizationService,
};
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::{authorizer::Require, ReadMetadata};
use trustify_common::{
    db::{query::Query, Database},
    model::Paginated,
};
use uuid::Uuid;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = OrganizationService::new(db);
    config
        .app_data(web::Data::new(service))
        .service(all)
        .service(get);
}

#[utoipa::path(
    tag = "organization",
    operation_id = "listOrganizations",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching organizations", body = OrganizationSummary),
    ),
)]
#[get("/v1/organization")]
/// List organizations
pub async fn all(
    state: web::Data<OrganizationService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadMetadata>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_organizations(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "organization",
    operation_id = "getOrganization",
    params(
        ("id", Path, description = "Opaque ID of the organization")
    ),
    responses(
        (status = 200, description = "Matching organization", body = OrganizationDetails),
        (status = 404, description = "Matching organization not found"),
    ),
)]
#[get("/v1/organization/{id}")]
/// Retrieve organization details
pub async fn get(
    state: web::Data<OrganizationService>,
    id: web::Path<Uuid>,
    _: Require<ReadMetadata>,
) -> actix_web::Result<impl Responder> {
    let fetched = state.fetch_organization(*id, ()).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
