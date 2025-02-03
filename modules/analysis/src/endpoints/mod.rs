mod query;

#[cfg(test)]
mod test;

use super::service::{AnalysisService, QueryOptions};
use crate::{
    endpoints::query::OwnedComponentReference,
    model::{AnalysisStatus, BaseSummary},
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
        .service(get_component)
        .service(search_component)
        .service(analysis_status)
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
    operation_id = "renderSbomGraph",
    params(
        ("sbom" = String, Path, description = "ID of the SBOM")
    ),
    responses(
        (status = 200, description = "A graphviz dot file of the SBOM graph", body = String),
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
        Ok(HttpResponse::Ok()
            .content_type("text/vnd.graphviz")
            .body(data))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
