use crate::model::advisory::{AdvisorySummary, AdvisoryVulnerabilitySummary};
use sea_orm::{EntityTrait, LoaderTrait};
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::{Database, Transactional};
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_cvss::cvss3::Cvss3Base;
use trustify_cvss::cvss3::score::Score;
use trustify_entity::{advisory, advisory_vulnerability, cvss3, vulnerability};
use trustify_module_search::model::SearchOptions;
use trustify_module_search::query::Query;

pub struct FetchService {
    db: Database,
}

impl FetchService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn fetch_advisories<TX: AsRef<Transactional>>(
        &self,
        search: SearchOptions,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<AdvisorySummary>, anyhow::Error> {
        let connection = self.db.connection(&tx);

        let limiter = advisory::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        let advisories = limiter.fetch().await?;

        let vulns = advisories
            .load_many_to_many(
                vulnerability::Entity,
                advisory_vulnerability::Entity,
                &self.db.connection(&tx),
            )
            .await?;

        let mut vuln_summaries = Vec::new();

        for vuln in vulns {
            let cvss3s = vuln
                .load_many(cvss3::Entity, &self.db.connection(&tx))
                .await?;

            let advisory_vulns: Vec<_> = vuln.iter().zip(cvss3s.iter()).map(|(vuln, cvss3)| {
                let score = if let Some(average) = cvss3
                    .iter()
                    .map(|e| {
                        let base = Cvss3Base::from(e.clone());
                        base.score().value()
                    })
                    .reduce(|accum, e| accum + e)
                {
                    Score::new(average / cvss3.len() as f64)
                } else {
                    Score::new(0.0)
                };

                AdvisoryVulnerabilitySummary {
                    vulnerability_id: vuln.identifier.clone(),
                    severity: score.severity().to_string(),
                    score: score.value()
                }
            }).collect();

            vuln_summaries.push( advisory_vulns );
        }

        let advisories: Vec<_> = advisories.iter().zip( vuln_summaries.iter())
            .map(|(advisory, summaries)| {
                AdvisorySummary {
                    identifier: advisory.identifier.clone(),
                    sha256: advisory.sha256.clone(),
                    published: advisory.published,
                    modified: advisory.modified,
                    withdrawn: advisory.withdrawn,
                    title: advisory.title.clone(),
                    vulnerabilities: summaries.clone(),
                }
            })
            .collect();

        Ok(PaginatedResults {
            total,
            items: advisories,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::service::FetchService;
    use actix_web::App;
    use std::sync::Arc;
    use test_log::test;
    use time::OffsetDateTime;
    use trustify_common::db::Database;
    use trustify_common::model::Paginated;
    use trustify_cvss::cvss3::{
        AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
        PrivilegesRequired, Scope, UserInteraction,
    };
    use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
    use trustify_module_ingestor::graph::Graph;
    use trustify_module_search::model::SearchOptions;

    #[test(actix_web::test)]
    async fn all_advisories() -> Result<(), anyhow::Error> {
        let db = Database::for_test("fetch_advisories").await?;
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

        fetch
            .fetch_advisories(SearchOptions::default(), Paginated::default(), ())
            .await?;

        Ok(())
    }
}
