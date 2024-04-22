use crate::endpoints::vulnerability::advisories;
use crate::endpoints::Error;
use crate::graph::Graph;
use crate::model::advisory::{
    AdvisoryDetails, AdvisorySummary, AdvisoryVulnerabilityDetails, AdvisoryVulnerabilitySummary,
};
use crate::model::vulnerability::Vulnerability;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::model::{Paginated, PaginatedResults};
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
    let tx = state.transaction().await.map_err(Error::System)?;

    let advisory_contexts = state
        .advisories(search, paginated, &tx)
        .await
        .map_err(Error::System)?;

    let mut results = PaginatedResults {
        items: vec![],
        total: advisory_contexts.total,
    };

    for advisory in advisory_contexts.items {
        let mut vulnerability_summaries = Vec::new();

        let advisory_vulnerabilities =
            advisory.vulnerabilities(&tx).await.map_err(Error::System)?;

        for advisory_vulnerability in advisory_vulnerabilities {
            if let Some(vulnerability) = advisory_vulnerability
                .vulnerability(&tx)
                .await
                .map_err(Error::System)?
            {
                let summary = AdvisoryVulnerabilitySummary {
                    vulnerability_id: vulnerability.vulnerability.identifier,
                    // TODO populate these
                    severity: "".to_string(),
                    score: 0.0,
                };
                vulnerability_summaries.push(summary);
            }
        }
        results.items.push(AdvisorySummary::new(
            advisory.advisory,
            vulnerability_summaries,
        ))
    }

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

                advisory_vulnerabilities.push(AdvisoryVulnerabilityDetails {
                    vulnerability_id: vuln.vulnerability.identifier,
                    cvss3_scores,
                    assertions,
                })
            }
        }

        let result_advisory = AdvisoryDetails::new(advisory.advisory, advisory_vulnerabilities);

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
    use trustify_cvss::cvss3::{
        AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
        PrivilegesRequired, Scope, UserInteraction,
    };

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

        let advisory_vuln = advisory.link_to_vulnerability("CVE-123", ()).await?;
        advisory_vuln
            .ingest_cvss3_score(
                Cvss3Base {
                    minor_version: 0,
                    av: AttackVector::Network,
                    ac: AttackComplexity::Low,
                    pr: PrivilegesRequired::None,
                    ui: UserInteraction::None,
                    s: Scope::Unchanged,
                    c: Confidentiality::None,
                    i: Integrity::None,
                    a: Availability::None,
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

        let rhsa_1 = &response.items.iter().find(|e| e.identifier == "RHSA-1");

        assert!(rhsa_1.is_some());

        let rhsa_1 = rhsa_1.unwrap();

        assert!(rhsa_1
            .vulnerabilities
            .iter()
            .any(|e| e.vulnerability_id == "CVE-123"));

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

        let advisory_vuln = advisory.link_to_vulnerability("CVE-123", ()).await?;
        advisory_vuln
            .ingest_cvss3_score(
                Cvss3Base {
                    minor_version: 0,
                    av: AttackVector::Network,
                    ac: AttackComplexity::Low,
                    pr: PrivilegesRequired::None,
                    ui: UserInteraction::None,
                    s: Scope::Unchanged,
                    c: Confidentiality::None,
                    i: Integrity::None,
                    a: Availability::None,
                },
                (),
            )
            .await?;

        let uri = "/api/v1/advisory/8675319";

        let request = TestRequest::get().uri(uri).to_request();

        let response: AdvisoryDetails =
            actix_web::test::call_and_read_body_json(&app, request).await;

        assert_eq!(1, response.vulnerabilities.len());

        let vuln = &response.vulnerabilities[0];

        assert_eq!(1, vuln.cvss3_scores.len());

        Ok(())
    }
}
