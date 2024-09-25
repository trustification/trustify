use super::*;
use crate::advisory::model::AdvisoryHead;
use crate::source_document::model::SourceDocument;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::{db::query::q, hashing::Digests, model::Paginated, purl::Purl};
use trustify_cvss::cvss3::severity::Severity;
use trustify_cvss::cvss3::{
    AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
    PrivilegesRequired, Scope, UserInteraction,
};
use trustify_module_ingestor::graph::advisory::{
    advisory_vulnerability::{VersionInfo, VersionSpec},
    AdvisoryContext, AdvisoryInformation,
};

use trustify_test_context::TrustifyContext;

pub async fn ingest_sample_advisory<'a>(
    ctx: &'a TrustifyContext,
    title: &'a str,
) -> Result<AdvisoryContext<'a>, trustify_module_ingestor::graph::error::Error> {
    ctx.graph
        .ingest_advisory(
            title,
            ("source", "http://redhat.com/"),
            &Digests::digest(title),
            AdvisoryInformation {
                title: Some(title.to_string()),
                version: None,
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await
}

pub async fn ingest_and_link_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let advisory = ingest_sample_advisory(ctx, "RHSA-1").await?;

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
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_and_link_advisory(ctx).await?;

    ingest_sample_advisory(ctx, "RHSA-2").await?;

    let fetch = AdvisoryService::new(ctx.db.clone());
    let fetched = fetch
        .fetch_advisories(q(""), Paginated::default(), Default::default(), ())
        .await?;

    assert_eq!(fetched.total, 2);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_advisories_filtered_by_average_score(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ingest_and_link_advisory(ctx).await?;

    ingest_sample_advisory(ctx, "RHSA-2").await?;

    let fetch = AdvisoryService::new(ctx.db.clone());
    let fetched = fetch
        .fetch_advisories(
            q("average_score>8"),
            Paginated::default(),
            Default::default(),
            (),
        )
        .await?;

    assert_eq!(fetched.total, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_advisories_filtered_by_average_severity(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ingest_and_link_advisory(ctx).await?;

    ingest_sample_advisory(ctx, "RHSA-2").await?;

    let fetch = AdvisoryService::new(ctx.db.clone());
    let fetched = fetch
        .fetch_advisories(
            q("average_severity>=critical"),
            Paginated::default(),
            Default::default(),
            (),
        )
        .await?;

    log::debug!("{:#?}", fetched);

    assert_eq!(fetched.total, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn single_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digests = Digests::digest("RHSA-1");

    let advisory = ingest_sample_advisory(ctx, "RHSA-1").await?;

    let advisory_vuln: trustify_module_ingestor::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext<'_> = advisory
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
        .ingest_package_status(
            None,
            &Purl::from_str("pkg://maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: "semver".to_string(),
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            (),
        )
        .await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg://maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: "semver".to_string(),
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            (),
        )
        .await?;

    ingest_sample_advisory(ctx, "RHSA-2").await?;

    let fetch = AdvisoryService::new(ctx.db.clone());
    let jenny256 = Id::sha256(&digests.sha256);
    let jenny384 = Id::sha384(&digests.sha384);
    let jenny512 = Id::sha512(&digests.sha512);
    let fetched = fetch.fetch_advisory(jenny256.clone(), ()).await?;

    assert!(matches!(
            fetched,
            Some(AdvisoryDetails {
                head: AdvisoryHead { .. },
            source_document: Some(SourceDocument {
                sha256,
                sha384,
                sha512,
                ..
            }),
            average_severity: Some(average_severity),

                ..
            })
        if sha256 == jenny256.to_string() && sha384 == jenny384.to_string() && sha512 == jenny512.to_string() && average_severity == Severity::Critical));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digests = Digests::digest("RHSA-1");

    let advisory = ingest_sample_advisory(ctx, "RHSA-1").await?;

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
        .ingest_package_status(
            None,
            &Purl::from_str("pkg://maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: "semver".to_string(),
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            (),
        )
        .await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg://maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: "semver".to_string(),
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            (),
        )
        .await?;

    let fetch = AdvisoryService::new(ctx.db.clone());
    let jenny256 = Id::sha256(&digests.sha256);
    let fetched = fetch.fetch_advisory(jenny256.clone(), ()).await?;

    let fetched = fetched.expect("Advisory not found");

    let affected = fetch.delete_advisory(fetched.head.uuid, ()).await?;
    assert_eq!(affected, 1);

    let affected = fetch.delete_advisory(fetched.head.uuid, ()).await?;
    assert_eq!(affected, 0);

    Ok(())
}
