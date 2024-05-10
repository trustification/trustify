//! Support for advisories.

use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::graph::error::Error;
use crate::graph::Graph;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, QueryFilter};
use sea_orm::{ColumnTrait, QuerySelect, RelationTrait};
use sea_query::{Condition, JoinType};
use std::fmt::{Debug, Formatter};
use time::OffsetDateTime;
use trustify_common::db::Transactional;
use trustify_entity as entity;
use trustify_entity::advisory;

pub mod advisory_vulnerability;

pub mod affected_package_version_range;
pub mod fixed_package_version;
pub mod not_affected_package_version;

#[derive(Clone, Default)]
pub struct AdvisoryInformation {
    pub title: Option<String>,
    pub issuer: Option<String>,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
}

impl AdvisoryInformation {
    pub fn has_data(&self) -> bool {
        self.title.is_some()
            || self.issuer.is_some()
            || self.published.is_some()
            || self.modified.is_some()
            || self.withdrawn.is_some()
    }
}

impl From<()> for AdvisoryInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

impl Graph {
    pub async fn get_advisory_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<AdvisoryContext>, Error> {
        Ok(entity::advisory::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    pub async fn get_advisory<TX: AsRef<Transactional>>(
        &self,
        sha256: &str,
        tx: TX,
    ) -> Result<Option<AdvisoryContext>, Error> {
        Ok(entity::advisory::Entity::find()
            .filter(Condition::all().add(entity::advisory::Column::Sha256.eq(sha256.to_string())))
            .one(&self.connection(&tx))
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    pub async fn ingest_advisory<TX: AsRef<Transactional>>(
        &self,
        identifier: impl Into<String>,
        location: impl Into<String>,
        sha256: impl Into<String>,
        information: impl Into<AdvisoryInformation>,
        tx: TX,
    ) -> Result<AdvisoryContext, Error> {
        let identifier = identifier.into();
        let location = location.into();
        let sha256 = sha256.into();
        let information = information.into();

        if let Some(found) = self.get_advisory(&sha256, &tx).await? {
            return Ok(found);
        }

        let organization = if let Some(issuer) = information.issuer {
            Some(self.ingest_organization(issuer, (), &tx).await?)
        } else {
            None
        };

        let model = entity::advisory::ActiveModel {
            id: Default::default(),
            identifier: Set(identifier),
            issuer_id: Set(organization.map(|org| org.organization.id)),
            location: Set(location),
            sha256: Set(sha256),
            title: Set(information.title),
            published: Set(information.published),
            modified: Set(information.modified),
            withdrawn: Default::default(),
        };

        Ok(AdvisoryContext::new(
            self,
            model.insert(&self.connection(&tx)).await?,
        ))
    }
}

#[derive(Clone)]
pub struct AdvisoryContext<'g> {
    graph: &'g Graph,
    pub advisory: entity::advisory::Model,
}

impl PartialEq for AdvisoryContext<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.advisory.eq(&other.advisory)
    }
}

impl Debug for AdvisoryContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.advisory.fmt(f)
    }
}

impl<'g> AdvisoryContext<'g> {
    pub fn new(graph: &'g Graph, advisory: advisory::Model) -> Self {
        Self { graph, advisory }
    }

    pub async fn set_published_at<TX: AsRef<Transactional>>(
        &self,
        published_at: time::OffsetDateTime,
        tx: TX,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.published = Set(Some(published_at));
        entity.save(&self.graph.connection(&tx)).await?;
        Ok(())
    }

    pub fn published_at(&self) -> Option<time::OffsetDateTime> {
        self.advisory.published
    }

    pub async fn set_modified_at<TX: AsRef<Transactional>>(
        &self,
        modified_at: time::OffsetDateTime,
        tx: TX,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.modified = Set(Some(modified_at));
        entity.save(&self.graph.connection(&tx)).await?;
        Ok(())
    }

    pub fn modified_at(&self) -> Option<time::OffsetDateTime> {
        self.advisory.modified
    }

    pub async fn set_withdrawn_at<TX: AsRef<Transactional>>(
        &self,
        withdrawn_at: time::OffsetDateTime,
        tx: TX,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.withdrawn = Set(Some(withdrawn_at));
        entity.save(&self.graph.connection(&tx)).await?;
        Ok(())
    }

    pub fn withdrawn_at(&self) -> Option<time::OffsetDateTime> {
        self.advisory.withdrawn
    }

    pub async fn get_vulnerability<TX: AsRef<Transactional>>(
        &self,
        identifier: &str,
        tx: TX,
    ) -> Result<Option<AdvisoryVulnerabilityContext<'g>>, Error> {
        Ok(entity::advisory_vulnerability::Entity::find()
            .join(
                JoinType::Join,
                entity::advisory_vulnerability::Relation::Vulnerability.def(),
            )
            .filter(entity::advisory_vulnerability::Column::AdvisoryId.eq(self.advisory.id))
            .filter(entity::vulnerability::Column::Identifier.eq(identifier))
            .one(&self.graph.connection(&tx))
            .await?
            .map(|vuln| (self, vuln).into()))
    }

    pub async fn link_to_vulnerability<TX: AsRef<Transactional>>(
        &self,
        identifier: &str,
        tx: TX,
    ) -> Result<AdvisoryVulnerabilityContext, Error> {
        if let Some(found) = self.get_vulnerability(identifier, &tx).await? {
            return Ok(found);
        }

        let vulnerability = self.graph.ingest_vulnerability(identifier, (), &tx).await?;

        let entity = entity::advisory_vulnerability::ActiveModel {
            advisory_id: Set(self.advisory.id),
            vulnerability_id: Set(vulnerability.vulnerability.id),
        };

        Ok((self, entity.insert(&self.graph.connection(&tx)).await?).into())
    }

    pub async fn vulnerabilities<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<AdvisoryVulnerabilityContext>, Error> {
        Ok(entity::advisory_vulnerability::Entity::find()
            .join(
                JoinType::Join,
                entity::advisory_vulnerability::Relation::Vulnerability.def(),
            )
            .filter(entity::advisory_vulnerability::Column::AdvisoryId.eq(self.advisory.id))
            .all(&self.graph.connection(&tx))
            .await?
            .drain(0..)
            .map(|e| (self, e).into())
            .collect())
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::{test::TrustifyContext, Transactional};

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory1 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let advisory2 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let advisory3 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "89",
                (),
                Transactional::None,
            )
            .await?;

        assert_eq!(advisory1.advisory.id, advisory2.advisory.id);
        assert_ne!(advisory1.advisory.id, advisory3.advisory.id);

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_affected_package_version_range(
        ctx: TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let advisory_vulnerability = advisory
            .link_to_vulnerability("CVE-8675309", Transactional::None)
            .await?;

        let affected1 = advisory_vulnerability
            .ingest_affected_package_range(
                &"pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let affected2 = advisory_vulnerability
            .ingest_affected_package_range(
                &"pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let affected3 = advisory_vulnerability
            .ingest_affected_package_range(
                &"pkg://maven/io.quarkus/quarkus-addons".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        assert_eq!(
            affected1.affected_package_version_range.id,
            affected2.affected_package_version_range.id
        );
        assert_ne!(
            affected1.affected_package_version_range.id,
            affected3.affected_package_version_range.id
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_fixed_package_version(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let advisory_vulnerability = advisory
            .link_to_vulnerability("CVE-1234567", Transactional::None)
            .await?;

        let _affected = advisory_vulnerability
            .ingest_affected_package_range(
                &"pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let fixed1 = advisory_vulnerability
            .ingest_fixed_package_version(
                &"pkg://maven/io.quarkus/quarkus-core@1.2.0".try_into()?,
                Transactional::None,
            )
            .await?;

        let fixed2 = advisory_vulnerability
            .ingest_fixed_package_version(
                &"pkg://maven/io.quarkus/quarkus-core@1.2.0".try_into()?,
                Transactional::None,
            )
            .await?;

        let fixed3 = advisory_vulnerability
            .ingest_fixed_package_version(
                &"pkg://maven/io.quarkus/quarkus-addons@1.2.0".try_into()?,
                Transactional::None,
            )
            .await?;

        assert_eq!(
            fixed1.fixed_package_version.id,
            fixed2.fixed_package_version.id
        );
        assert_ne!(
            fixed1.fixed_package_version.id,
            fixed3.fixed_package_version.id
        );

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_advisory_cve(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        advisory
            .link_to_vulnerability("CVE-123", Transactional::None)
            .await?;
        advisory
            .link_to_vulnerability("CVE-123", Transactional::None)
            .await?;
        advisory
            .link_to_vulnerability("CVE-456", Transactional::None)
            .await?;

        Ok(())
    }
}
