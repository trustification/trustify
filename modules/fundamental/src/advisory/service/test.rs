use super::*;
use crate::advisory::model::AdvisoryHead;
use std::str::FromStr;
use std::sync::Arc;
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::db::{query::q, test::TrustifyContext};
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::{
    AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
    PrivilegesRequired, Scope, UserInteraction,
};
use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
use trustify_module_ingestor::graph::Graph;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    let advisory = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
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
                i: Integrity::High,
                a: Availability::High,
            },
            (),
        )
        .await?;

    graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let fetch = AdvisoryService::new(db);
    let fetched = fetch
        .fetch_advisories(q(""), Paginated::default(), ())
        .await?;

    assert_eq!(fetched.total, 2);
    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_advisories_filtered_by_average_score(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    let advisory = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
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
                i: Integrity::High,
                a: Availability::High,
            },
            (),
        )
        .await?;

    graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let fetch = AdvisoryService::new(db);
    let fetched = fetch
        .fetch_advisories(q("average_score>8"), Paginated::default(), ())
        .await?;

    assert_eq!(fetched.total, 1);
    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_advisories_filtered_by_average_severity(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    let advisory = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
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
                i: Integrity::High,
                a: Availability::High,
            },
            (),
        )
        .await?;

    graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let fetch = AdvisoryService::new(db);
    let fetched = fetch
        .fetch_advisories(q("average_severity>=critical"), Paginated::default(), ())
        .await?;

    println!("{:#?}", fetched);

    assert_eq!(fetched.total, 1);
    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn single_advisory(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    let advisory = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
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
                i: Integrity::High,
                a: Availability::High,
            },
            (),
        )
        .await?;

    advisory_vuln
        .ingest_fixed_package_version(&Purl::from_str("pkg://maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let fetch = AdvisoryService::new(db);
    let jenny = Id::from_str("sha256:8675309")?;
    let fetched = fetch.fetch_advisory(jenny.clone(), ()).await?;

    assert!(matches!(
            fetched,
            Some(AdvisoryDetails {
                head: AdvisoryHead { hashes, .. },
            average_severity: Some(average_severity),

                ..
            })
        if hashes.contains(&jenny) && average_severity == "critical"));

    Ok(())
}
