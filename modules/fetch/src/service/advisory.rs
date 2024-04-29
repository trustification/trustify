
use crate::error::Error;
use crate::model::advisory::{AdvisoryDetails, AdvisorySummary};
use crate::model::vulnerability::{VulnerabilityDetails, VulnerabilitySummary};
use sea_orm::{ColumnTrait, EntityTrait, LoaderTrait, QueryFilter};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use trustify_common::advisory::{AdvisoryVulnerabilityAssertions, Assertion};
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::{Database, Transactional};
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::score::Score;
use trustify_cvss::cvss3::Cvss3Base;
use trustify_entity::{
    advisory, advisory_vulnerability, affected_package_version_range, cvss3, fixed_package_version,
    not_affected_package_version, package, package_version, package_version_range, vulnerability,
};
use trustify_module_search::model::SearchOptions;
use trustify_module_search::query::Query;

pub enum AdvisoryKey {
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

impl super::FetchService {

    pub(crate) async fn advisory_summaries<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        advisories: &Vec<advisory::Model>,
        tx: TX,
    ) -> Result<Vec<AdvisorySummary>, Error> {
        let mut vulns = advisories
            .load_many_to_many(
                vulnerability::Entity,
                advisory_vulnerability::Entity,
                &self.db.connection(&tx),
            )
            .await?;

        let mut advisory_summaries = Vec::new();

        for (advisory, mut vuln) in advisories.iter().zip(vulns.drain(..)) {
            let vulnerabilities = self
                .vulnerability_summaries_for_advisory(&vuln, advisory.id, &tx)
                .await?;

            advisory_summaries.push(AdvisorySummary {
                identifier: advisory.identifier.clone(),
                sha256: advisory.sha256.clone(),
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title.clone(),
                vulnerabilities,
            })
        }

        Ok(advisory_summaries)
    }

    pub async fn fetch_advisories<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        search: SearchOptions,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<AdvisorySummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = advisory::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            total,
            items: self.advisory_summaries(&limiter.fetch().await?, tx).await?,
        })
    }

    pub async fn fetch_advisory<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        key: AdvisoryKey,
        tx: TX,
    ) -> Result<Option<AdvisoryDetails>, Error> {
        let mut results = advisory::Entity::find()
            .filter(match key {
                AdvisoryKey::Sha256(digest) => advisory::Column::Sha256.eq(digest),
                AdvisoryKey::Sha384(digest) => {
                    todo!("supporter sha384")
                }
                AdvisoryKey::Sha512(digest) => {
                    todo!("supporter sha512")
                }
            })
            .find_with_related(vulnerability::Entity)
            .all(&self.db.connection(&tx))
            .await?;

        if results.is_empty() {
            return Ok(None);
        }

        let (advisory, mut vulnerabilities) = results.remove(0);

        let vulnerabilities = self
            .vulnerability_details(&vulnerabilities, Some(advisory.id), &tx)
            .await?;

        Ok(Some(AdvisoryDetails {
            summary: AdvisorySummary {
                identifier: advisory.identifier,
                sha256: advisory.sha256,
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title,
                vulnerabilities: vec![],
            },
            vulnerabilities,
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::FetchService;
    use actix_web::App;
    use std::str::FromStr;
    use std::sync::Arc;
    use test_context::test_context;
    use test_log::test;
    use time::OffsetDateTime;
    use trustify_common::db::{test::TrustifyContext, Database};
    use trustify_common::model::Paginated;
    use trustify_common::purl::Purl;
    use trustify_cvss::cvss3::{
        AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
        PrivilegesRequired, Scope, UserInteraction,
    };
    use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
    use trustify_module_ingestor::graph::Graph;
    use trustify_module_search::model::SearchOptions;

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
                    i: Integrity::High,
                    a: Availability::High,
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

        let fetch = FetchService::new(db);

        let fetched = fetch
            .fetch_advisories(SearchOptions::default(), Paginated::default(), ())
            .await?;

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
                    i: Integrity::High,
                    a: Availability::High,
                },
                (),
            )
            .await?;

        advisory_vuln
            .ingest_fixed_package_version(
                &Purl::from_str("pkg://maven/org.apache/log4j@1.2.3")?,
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

        let fetch = FetchService::new(db);

        let fetched = fetch
            .fetch_advisory(AdvisoryKey::Sha256("8675309".to_string()), ())
            .await?;

        Ok(())
    }
}
