use crate::endpoints::vulnerability::advisories;
use crate::endpoints::Error;
use crate::graph::Graph;
use crate::model::advisory::{AdvisoryDetails, AdvisorySummary, AdvisoryVulnerability};
use crate::model::vulnerability::Vulnerability;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::model::Paginated;
use trustify_module_search::model::SearchOptions;

#[utoipa::path(
    context_path = "/api/v1/advisory",
    tag = "advisory",
    params(
        SearchOptions,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("")]
pub async fn all(
    state: web::Data<Graph>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    let results = state
        .advisories(search, paginated, ())
        .await
        .map_err(Error::System)?
        .map(|e| AdvisorySummary::from(e.advisory));

    Ok(HttpResponse::Ok().json(results))
}

#[utoipa::path(
    context_path = "/api/v1/advisory",
    tag = "advisory",
    params(
        SearchOptions,
        Paginated,
        ("sha256", Path, description = "SHA256 of the advisory")
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
    ),
)]
#[get("/{sha256}")]
pub async fn get(
    state: web::Data<Graph>,
    web::Query(sha256): web::Query<String>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    let tx = state.transaction().await.map_err(Error::System)?;
    if let Some(advisory) = state
        .get_advisory(&sha256, &tx)
        .await
        .map_err(Error::System)?
    {
        let mut advisory_vulnerabilities = Vec::new();
        for advisory_vuln in &advisory.vulnerabilities(&tx).await.map_err(Error::System)? {
            if let Some(vuln) = advisory_vuln
                .vulnerability(&tx)
                .await
                .map_err(Error::System)?
            {
                let cvss3_scores = advisory_vuln
                    .cvss3_scores(&tx)
                    .await
                    .map_err(Error::System)?;

                // TODO: cvss4 scores

                let assertions = advisory_vuln
                    .vulnerability_assertions(&tx)
                    .await
                    .map_err(Error::System)?;

                advisory_vulnerabilities.push(AdvisoryVulnerability {
                    vulnerability_id: vuln.vulnerability.identifier,
                    cvss3_scores,
                    assertions,
                })
            }
        }

        let result_advisory =
            AdvisoryDetails::new_summary(advisory.advisory, advisory_vulnerabilities);

        Ok(HttpResponse::Ok().json(result_advisory))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
