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
("sha256", Path, description = "SHA256 of the advisory")
),
responses(
(status = 200, description = "Matching advisory", body = AdvisoryDetails),
),
)]
#[get("/{sha256}")]
pub async fn get(
    state: web::Data<Graph>,
    sha256: web::Path<String>,
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
                    .map_err(Error::System)?
                    .drain(..)
                    .map(|e| e.to_string())
                    .collect();

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

        println!("RETURN {:#?}", result_advisory);

        Ok(HttpResponse::Ok().json(result_advisory))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[cfg(test)]
mod test {
    use crate::graph::advisory::AdvisoryInformation;
    use crate::graph::Graph;
    use crate::model::advisory::{AdvisoryDetails, AdvisorySummary};
    use crate::model::vulnerability::Vulnerability;
    use actix_web::test::TestRequest;
    use actix_web::{web, App};
    use std::sync::Arc;
    use test_log::test;
    use time::OffsetDateTime;
    use trustify_common::db::Database;
    use trustify_common::model::PaginatedResults;

    #[test(actix_web::test)]
    async fn all_advisories() -> Result<(), anyhow::Error> {
        let db = Database::for_test("api_all_advisories").await?;
        let graph = Arc::new(Graph::new(db));

        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::from(graph.clone()))
                .configure(crate::endpoints::configure),
        )
        .await;

        let advisory = graph
            .ingest_advisory(
                "RHSA-1",
                "http://redhat.com/",
                "8675309",
                AdvisoryInformation {
                    title: Some("RHSA-1".to_string()),
                    published: Some(OffsetDateTime::now_utc()),
                    modified: None,
                },
                (),
            )
            .await?;

        let advisory = graph
            .ingest_advisory(
                "RHSA-2",
                "http://redhat.com/",
                "8675319",
                AdvisoryInformation {
                    title: Some("RHSA-2".to_string()),
                    published: Some(OffsetDateTime::now_utc()),
                    modified: None,
                },
                (),
            )
            .await?;

        let uri = "/api/v1/advisory";

        let request = TestRequest::get().uri(uri).to_request();

        let response: PaginatedResults<AdvisorySummary> =
            actix_web::test::call_and_read_body_json(&app, request).await;

        assert_eq!(2, response.items.len());

        Ok(())
    }

    #[test(actix_web::test)]
    async fn one_advisory() -> Result<(), anyhow::Error> {
        let db = Database::for_test("api_one_advisory").await?;
        let graph = Arc::new(Graph::new(db));

        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::from(graph.clone()))
                .configure(crate::endpoints::configure),
        )
        .await;

        let advisory = graph
            .ingest_advisory(
                "RHSA-1",
                "http://redhat.com/",
                "8675309",
                AdvisoryInformation {
                    title: Some("RHSA-1".to_string()),
                    published: Some(OffsetDateTime::now_utc()),
                    modified: None,
                },
                (),
            )
            .await?;

        let advisory = graph
            .ingest_advisory(
                "RHSA-2",
                "http://redhat.com/",
                "8675319",
                AdvisoryInformation {
                    title: Some("RHSA-2".to_string()),
                    published: Some(OffsetDateTime::now_utc()),
                    modified: None,
                },
                (),
            )
            .await?;

        let uri = "/api/v1/advisory/8675319";

        let request = TestRequest::get().uri(uri).to_request();

        let response: AdvisoryDetails =
            actix_web::test::call_and_read_body_json(&app, request).await;

        println!("{:#?}", response);

        Ok(())
    }
}
