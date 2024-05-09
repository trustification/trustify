use crate::error::Error;
use crate::model::advisory::{
    AdvisoryDetails, AdvisoryHead, AdvisorySummary, AdvisoryVulnerabilityHead,
    AdvisoryVulnerabilitySummary,
};
use crate::model::vulnerability::{VulnerabilityDetails, VulnerabilityHead, VulnerabilitySummary};
use crate::query::{Query, SearchOptions};
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

pub enum AdvisoryKey {
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

impl super::FetchService {
    pub(crate) async fn advisory_heads<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        advisories: &[advisory::Model],
        tx: TX,
    ) -> Result<Vec<AdvisoryHead>, Error> {
        let mut heads = Vec::new();

        for advisory in advisories.iter() {
            heads.push(AdvisoryHead {
                identifier: advisory.identifier.clone(),
                sha256: advisory.sha256.clone(),
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title.clone(),
            })
        }

        Ok(heads)
    }

    pub(crate) async fn advisory_vulnerability_heads<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        advisory_id: i32,
        vulnerabilities: &Vec<vulnerability::Model>,
        tx: TX,
    ) -> Result<Vec<AdvisoryVulnerabilityHead>, Error> {
        let mut cvss3s = vulnerabilities
            .load_many(
                cvss3::Entity::find().filter(cvss3::Column::AdvisoryId.eq(advisory_id)),
                &self.db.connection(&tx),
            )
            .await?;

        let mut heads = Vec::new();

        for ((vuln, cvss3)) in vulnerabilities.iter().zip(cvss3s.iter()) {
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
            if let Some(head) = self.vulnerability_head(vuln, &tx).await? {
                heads.push(AdvisoryVulnerabilityHead {
                    head,
                    severity: score.severity().to_string(),
                    score: score.value(),
                });
            }
        }

        Ok(heads)
    }
    pub(crate) async fn advisory_vulnerability_head<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        advisory_id: i32,
        vulnerability: &vulnerability::Model,
        tx: TX,
    ) -> Result<Option<AdvisoryVulnerabilityHead>, Error> {
        Ok(self
            .advisory_vulnerability_heads(advisory_id, &vec![vulnerability.clone()], tx)
            .await?
            .first()
            .cloned())
    }

    pub async fn advisory_vulnerability_summaries<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        advisory_id: i32,
        vulnerabilities: &Vec<vulnerability::Model>,
        tx: TX,
    ) -> Result<Vec<AdvisoryVulnerabilitySummary>, Error> {
        let mut fixed = vulnerabilities
            .load_many(
                fixed_package_version::Entity::find()
                    .filter(fixed_package_version::Column::AdvisoryId.eq(advisory_id)),
                &self.db.connection(&tx),
            )
            .await?;

        let mut affected = vulnerabilities
            .load_many(
                affected_package_version_range::Entity::find()
                    .filter(affected_package_version_range::Column::AdvisoryId.eq(advisory_id)),
                &self.db.connection(&tx),
            )
            .await?;

        let mut not_affected = vulnerabilities
            .load_many(
                not_affected_package_version::Entity::find()
                    .filter(not_affected_package_version::Column::AdvisoryId.eq(advisory_id)),
                &self.db.connection(&tx),
            )
            .await?;

        let mut cvss3s = vulnerabilities
            .load_many(
                cvss3::Entity::find().filter(cvss3::Column::AdvisoryId.eq(advisory_id)),
                &self.db.connection(&tx),
            )
            .await?;

        let mut summaries = Vec::new();

        for ((((vuln, mut fixed), mut affected), mut not_affected), mut cvss3) in vulnerabilities
            .iter()
            .zip(fixed.drain(..))
            .zip(affected.drain(..))
            .zip(not_affected.drain(..))
            .zip(cvss3s.drain(..))
        {
            let mut assertions = HashMap::new();

            'fixed: {
                let mut package_versions = fixed
                    .load_one(package_version::Entity, &self.db.connection(&tx))
                    .await?
                    .iter()
                    .flat_map(|e| e.clone())
                    .collect::<Vec<_>>();

                let mut packages = package_versions
                    .load_one(package::Entity, &self.db.connection(&tx))
                    .await?;

                packages.drain(..).zip(package_versions.drain(..)).for_each(
                    |(package, version)| {
                        if let Some(package) = package {
                            let package_assertions = assertions
                                .entry(
                                    Purl {
                                        ty: package.r#type,
                                        namespace: package.namespace,
                                        name: package.name,
                                        version: None,
                                        qualifiers: Default::default(),
                                    }
                                    .to_string(),
                                )
                                .or_insert(vec![]);

                            package_assertions.push(Assertion::Fixed {
                                version: version.version,
                            })
                        }
                    },
                );
            }

            'affected: {
                let mut package_version_ranges = affected
                    .load_one(package_version_range::Entity, &self.db.connection(&tx))
                    .await?
                    .iter()
                    .flat_map(|e| e.clone())
                    .collect::<Vec<_>>();

                let mut packages = package_version_ranges
                    .load_one(package::Entity, &self.db.connection(&tx))
                    .await?
                    .drain(..)
                    .collect::<Vec<_>>();

                packages
                    .drain(..)
                    .zip(package_version_ranges.drain(..))
                    .for_each(|(package, version_range)| {
                        if let Some(package) = package {
                            let package_assertions = assertions
                                .entry(
                                    Purl {
                                        ty: package.r#type,
                                        namespace: package.namespace,
                                        name: package.name,
                                        version: None,
                                        qualifiers: Default::default(),
                                    }
                                    .to_string(),
                                )
                                .or_insert(vec![]);

                            package_assertions.push(Assertion::Affected {
                                start_version: version_range.start,
                                end_version: version_range.end,
                            })
                        }
                    });
            }

            'not_affected: {
                let mut package_versions = not_affected
                    .load_one(package_version::Entity, &self.db.connection(&tx))
                    .await?
                    .iter()
                    .flat_map(|e| e.clone())
                    .collect::<Vec<_>>();

                let mut packages = package_versions
                    .load_one(package::Entity, &self.db.connection(&tx))
                    .await?
                    .drain(..)
                    .collect::<Vec<_>>();

                packages.drain(..).zip(package_versions.drain(..)).for_each(
                    |(package, version)| {
                        if let Some(package) = package {
                            let package_assertions = assertions
                                .entry(
                                    Purl {
                                        ty: package.r#type,
                                        namespace: package.namespace,
                                        name: package.name,
                                        version: None,
                                        qualifiers: Default::default(),
                                    }
                                    .to_string(),
                                )
                                .or_insert(vec![]);

                            package_assertions.push(Assertion::NotAffected {
                                version: version.version,
                            })
                        }
                    },
                );

                let cvss3_scores = cvss3
                    .drain(..)
                    .map(|e| Cvss3Base::from(e).to_string())
                    .collect();

                if let Some(head) = self
                    .advisory_vulnerability_head(advisory_id, vuln, &tx)
                    .await?
                {
                    summaries.push(AdvisoryVulnerabilitySummary {
                        head,
                        cvss3_scores,
                        assertions: Default::default(),
                    });
                }
            }
        }

        Ok(summaries)
    }

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

        let mut summaries = Vec::new();

        for (advisory, mut vuln) in advisories.iter().zip(vulns.drain(..)) {
            let vulnerabilities = self
                .advisory_vulnerability_heads(advisory.id, &vuln, &tx)
                .await?;

            summaries.push(AdvisorySummary {
                head: AdvisoryHead {
                    identifier: advisory.identifier.clone(),
                    sha256: advisory.sha256.clone(),
                    published: advisory.published,
                    modified: advisory.modified,
                    withdrawn: advisory.withdrawn,
                    title: advisory.title.clone(),
                },
                vulnerabilities,
            })
        }

        Ok(summaries)
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
            .advisory_vulnerability_summaries(advisory.id, &vulnerabilities, &tx)
            .await?;

        Ok(Some(AdvisoryDetails {
            head: AdvisoryHead {
                identifier: advisory.identifier,
                sha256: advisory.sha256,
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title,
            },
            vulnerabilities,
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::query::SearchOptions;
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
                    withdrawn: None,
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
                    withdrawn: None,
                },
                (),
            )
            .await?;

        let fetch = FetchService::new(db);
        let fetched = fetch
            .fetch_advisories(SearchOptions::default(), Paginated::default(), ())
            .await?;
        assert_eq!(fetched.total, 2);
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
                    withdrawn: None,
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
                    withdrawn: None,
                },
                (),
            )
            .await?;

        let fetch = FetchService::new(db);
        let jenny = "8675309".to_string();
        let fetched = fetch.fetch_advisory(AdvisoryKey::Sha256(jenny), ()).await?;
        assert!(matches!(
            fetched,
            Some(AdvisoryDetails {
                head: AdvisoryHead { sha256: jenny, .. },
                ..
            })
        ));

        Ok(())
    }
}
