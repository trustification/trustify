mod query;

#[cfg(test)]
mod test;

use super::service::{AnalysisService, QueryOptions};
use crate::{
    endpoints::query::OwnedComponentReference,
    model::{AnalysisStatus, BaseSummary, Node, RootTraces},
};
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::{
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
    Permission, ReadSbom,
};
use trustify_common::{
    db::{query::Query, Database},
    model::{Paginated, PaginatedResults},
};
use utoipa_actix_web::service_config::ServiceConfig;

pub fn configure(config: &mut ServiceConfig, db: Database, analysis: AnalysisService) {
    config
        .app_data(web::Data::new(analysis))
        .app_data(web::Data::new(db))
        .service(search_component_root_components)
        .service(get_component_root_components)
        .service(get_component)
        .service(search_component)
        .service(analysis_status)
        .service(search_component_deps)
        .service(get_component_deps)
        .service(render_sbom_graph);
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "status",
    responses(
        (status = 200, description = "Analysis status.", body = AnalysisStatus),
    ),
)]
#[get("/v2/analysis/status")]
pub async fn analysis_status(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    user: UserInformation,
    authorizer: web::Data<Authorizer>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;
    Ok(HttpResponse::Ok().json(service.status(db.as_ref()).await?))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "searchComponentRootComponents",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Search component(s) and return their root components.", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/root-component")]
pub async fn search_component_root_components(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&search, QueryOptions::ancestors(), paginated, db.as_ref())
            .await?
            .root_traces(),
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getComponentRootComponents",
    params(
        ("key" = String, Path, description = "provide component name, URL-encoded pURL, or CPE itself"),
        Paginated,
    ),
    responses(
        (status = 200, description = "Retrieve component(s) root components by name, pURL, or CPE.", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/root-component/{key}")]
pub async fn get_component_root_components(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let query = OwnedComponentReference::try_from(key.as_str())?;

    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&query, QueryOptions::ancestors(), paginated, db.as_ref())
            .await?
            .root_traces(),
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getComponent",
    params(
        ("key" = String, Path, description = "provide component name, URL-encoded pURL, or CPE itself"),
        Query,
        Paginated,
        QueryOptions,
    ),
    responses(
        (status = 200, description = "Retrieve component(s) root components by name, pURL, or CPE.", body = PaginatedResults<BaseSummary>),
    ),
)]
#[get("/v2/analysis/component/{key}")]
pub async fn get_component(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(options): web::Query<QueryOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let query = OwnedComponentReference::try_from(key.as_str())?;

    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&query, options, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "searchComponent",
    params(
        Query,
        Paginated,
        QueryOptions,
    ),
    responses(
        (status = 200, description = "Retrieve component(s) root components by name, pURL, or CPE.", body = PaginatedResults<BaseSummary>),
    ),
)]
#[get("/v2/analysis/component")]
pub async fn search_component(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(options): web::Query<QueryOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&search, options, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "searchComponentDeps",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Search component(s) and return their deps.", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/dep")]
pub async fn search_component_deps(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&search, QueryOptions::descendants(), paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getComponentDeps",
    params(
        ("key" = String, Path, description = "provide component name or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Retrieve component(s) dep components by name or pURL.", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/dep/{key}")]
pub async fn get_component_deps(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let query = OwnedComponentReference::try_from(key.as_str())?;
    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&query, QueryOptions::descendants(), paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "renderSbomGraph",
    params(
        ("sbom" = String, Path, description = "ID of the SBOM")
    ),
    responses(
        (status = 200, description = "A graphwiz dot file of the SBOM graph", body = String),
        (status = 404, description = "The SBOM was not found"),
    ),
)]
#[get("/v2/analysis/sbom/{sbom}/render")]
pub async fn render_sbom_graph(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    sbom: web::Path<String>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    service.load_graph(db.as_ref(), &sbom).await;

    if let Some(data) = service.render_dot(&sbom) {
        Ok(HttpResponse::Ok().body(data))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
