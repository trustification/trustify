use crate::analysis::service::AnalysisService;
use crate::Error;
use actix_web::{get, web, HttpResponse, Responder};
use std::str::FromStr;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let graph_service = AnalysisService::new(db);

    config
        .app_data(web::Data::new(graph_service))
        .service(search_component_root_components)
        .service(get_component_root_components);
}

#[utoipa::path(
    context_path = "/api",
    tag = "analysis",
    operation_id = "searchComponentRootComponents",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Search component(s) and return their root components.", body = PackageNode),
    ),
)]
#[get("/v1/analysis/root-component")]
pub async fn search_component_root_components(
    service: web::Data<AnalysisService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve_root_components(search, paginated, ())
            .await?,
    ))
}

#[utoipa::path(
    context_path= "/api",
    tag = "analysis",
    operation_id = "getComponentRootComponents",
    params(
        ("key" = String, Path, description = "provide component name or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Retrieve component(s) root components by name or pURL.", body = PackageNode),
    ),
)]
#[get("/v1/analysis/root-component/{key}")]
pub async fn get_component_root_components(
    service: web::Data<AnalysisService>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg") {
        let purl: Purl = Purl::from_str(&key).map_err(Error::Purl)?;

        Ok(HttpResponse::Ok().json(
            service
                .retrieve_root_components_by_purl(purl, paginated, ())
                .await?,
        ))
    } else {
        Ok(HttpResponse::Ok().json(
            service
                .retrieve_root_components_by_name(key.to_string(), paginated, ())
                .await?,
        ))
    }
}

#[cfg(test)]
mod test;
