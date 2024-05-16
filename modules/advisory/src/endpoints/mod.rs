use crate::service::{AdvisoryKey, AdvisoryService};
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let service = AdvisoryService::new(db);
    config
        .app_data(web::Data::new(service))
        .service(all)
        .service(get);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, get),
    components(schemas(
        trustify_model::advisory::AdvisoryDetails,
        trustify_model::advisory::AdvisoryHead,
        trustify_model::advisory::AdvisorySummary,
        trustify_model::advisory::AdvisoryVulnerabilityHead,
        trustify_model::advisory::AdvisoryVulnerabilitySummary,
        trustify_model::advisory::PaginatedAdvisorySummary,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
        trustify_common::purl::Purl,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "advisory",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/advisory")]
pub async fn all(
    state: web::Data<AdvisoryService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_advisories(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "advisory",
    params(
        ("sha256", Path, description = "SHA256 of the advisory")
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "Matching advisory not found"),
    ),
)]
#[get("/api/v1/advisory/{sha256}")]
pub async fn get(
    state: web::Data<AdvisoryService>,
    sha256: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let fetched = state
        .fetch_advisory(AdvisoryKey::Sha256(sha256.to_string()), ())
        .await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[cfg(test)]
mod test;
