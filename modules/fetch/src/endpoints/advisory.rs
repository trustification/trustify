use crate::{service::advisory::AdvisoryKey, service::FetchService};
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
    state: web::Data<FetchService>,
    web::Query(search): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_advisories(search, paginated, ()).await?))
}

#[utoipa::path(
    context_path = "/api/v1/advisory",
    tag = "advisory",
    params(
        ("sha256", Path, description = "SHA256 of the advisory")
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "Matching advisory not found"),
    ),
)]
#[get("/{sha256}")]
pub async fn get(
    state: web::Data<FetchService>,
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
mod test {
    use actix_web::test::TestRequest;
    use actix_web::App;
    use serde_json::Value;
    use std::str::FromStr;
    use test_context::test_context;
    use test_log::test;
    use time::OffsetDateTime;

    use trustify_common::db::test::TrustifyContext;
    use trustify_common::model::PaginatedResults;
    use trustify_common::purl::Purl;
    use trustify_cvss::cvss3::{
        AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
        PrivilegesRequired, Scope, UserInteraction,
    };
    use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
    use trustify_module_ingestor::graph::Graph;

    use crate::model::advisory::{AdvisoryDetails, AdvisorySummary};

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(actix_web::test)]
    async fn all_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db.clone());

        let app = actix_web::test::init_service(
            App::new().configure(|mut config| crate::endpoints::configure(config, db)),
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

        let rhsa_1 = &response
            .items
            .iter()
            .find(|e| e.head.identifier == "RHSA-1");

        assert!(rhsa_1.is_some());

        let rhsa_1 = rhsa_1.unwrap();

        assert!(rhsa_1
            .vulnerabilities
            .iter()
            .any(|e| e.head.identifier == "CVE-123"));

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(actix_web::test)]
    async fn one_advisory(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let graph = Graph::new(db.clone());

        let app = actix_web::test::init_service(
            App::new().configure(|mut config| crate::endpoints::configure(config, db)),
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
                    pr: PrivilegesRequired::High,
                    ui: UserInteraction::None,
                    s: Scope::Changed,
                    c: Confidentiality::High,
                    i: Integrity::None,
                    a: Availability::None,
                },
                (),
            )
            .await?;

        advisory_vuln
            .ingest_not_affected_package_version(
                &Purl::from_str("pkg://maven/log4j/log4j@1.2.3")?,
                (),
            )
            .await?;

        let uri = "/api/v1/advisory/8675319";

        let request = TestRequest::get().uri(uri).to_request();

        /*
        let response: Value =
            actix_web::test::call_and_read_body_json(&app, request).await;

        println!("{:#?}", response);

         */

        let response: AdvisoryDetails =
            actix_web::test::call_and_read_body_json(&app, request).await;

        log::debug!("{:#?}", response);

        assert_eq!(1, response.vulnerabilities.len());

        let vuln = &response.vulnerabilities[0];

        assert_eq!(1, vuln.cvss3_scores.len());

        Ok(())
    }
}
