//! Support for advisories.

use crate::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext;
use crate::graph::error::Error;
use crate::graph::Graph;
use hex::ToHex;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, ModelTrait, QueryFilter};
use sea_orm::{ColumnTrait, QuerySelect, RelationTrait};
use sea_query::{Condition, JoinType, OnConflict};
use std::fmt::{Debug, Formatter};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::db::Transactional;
use trustify_common::hashing::Digests;
use trustify_entity as entity;
use trustify_entity::labels::Labels;
use trustify_entity::{advisory, source_document};
use uuid::Uuid;

pub mod advisory_vulnerability;

#[derive(Clone, Default)]
pub struct AdvisoryInformation {
    pub title: Option<String>,
    pub issuer: Option<String>,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
}

pub struct AdvisoryVulnerabilityInformation {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub discovery_date: Option<OffsetDateTime>,
    pub release_date: Option<OffsetDateTime>,
    pub cwes: Option<Vec<String>>,
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
        id: Uuid,
        tx: TX,
    ) -> Result<Option<AdvisoryContext>, Error> {
        Ok(entity::advisory::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    #[instrument(skip(self, tx), err(level=tracing::Level::INFO))]
    pub async fn get_advisory_by_digest<TX: AsRef<Transactional>>(
        &self,
        digest: &str,
        tx: TX,
    ) -> Result<Option<AdvisoryContext>, Error> {
        Ok(entity::advisory::Entity::find()
            .join(
                JoinType::Join,
                entity::advisory::Relation::SourceDocument.def(),
            )
            .filter(
                Condition::any()
                    .add(entity::source_document::Column::Sha256.eq(digest.to_string()))
                    .add(entity::source_document::Column::Sha384.eq(digest.to_string()))
                    .add(entity::source_document::Column::Sha512.eq(digest.to_string())),
            )
            .one(&self.connection(&tx))
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    pub async fn get_advisories<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<AdvisoryContext>, Error> {
        Ok(advisory::Entity::find()
            .all(&self.db.connection(&tx))
            .await?
            .into_iter()
            .map(|advisory| AdvisoryContext::new(self, advisory))
            .collect())
    }

    #[instrument(skip(self, labels, information, tx), err(level=tracing::Level::INFO))]
    pub async fn ingest_advisory<TX: AsRef<Transactional>>(
        &self,
        identifier: impl Into<String> + Debug,
        labels: impl Into<Labels>,
        digests: &Digests,
        information: impl Into<AdvisoryInformation>,
        tx: TX,
    ) -> Result<AdvisoryContext, Error> {
        let identifier = identifier.into();
        let labels = labels.into();
        let sha256 = digests.sha256.encode_hex::<String>();
        let information = information.into();

        if let Some(found) = self.get_advisory_by_digest(&sha256, &tx).await? {
            return Ok(found);
        }

        let organization = if let Some(issuer) = information.issuer {
            Some(self.ingest_organization(issuer, (), &tx).await?)
        } else {
            None
        };

        let doc_model = source_document::ActiveModel {
            id: Default::default(),
            sha256: Set(sha256),
            sha384: Set(digests.sha384.encode_hex()),
            sha512: Set(digests.sha512.encode_hex()),
        };

        let doc = doc_model.insert(&self.connection(&tx)).await?;

        let model = advisory::ActiveModel {
            id: Default::default(),
            identifier: Set(identifier),
            issuer_id: Set(organization.map(|org| org.organization.id)),
            title: Set(information.title),
            published: Set(information.published),
            modified: Set(information.modified),
            withdrawn: Default::default(),
            labels: Set(labels),
            source_document_id: Set(Some(doc.id)),
        };

        Ok(AdvisoryContext::new(
            self,
            model.insert(&self.connection(&tx)).await?,
        ))
    }
}

#[derive(Clone)]
pub struct AdvisoryContext<'g> {
    pub graph: &'g Graph,
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

    #[instrument(skip(self, tx), err(level=tracing::Level::INFO))]
    pub async fn get_vulnerability<TX: AsRef<Transactional>>(
        &self,
        identifier: &str,
        tx: TX,
    ) -> Result<Option<AdvisoryVulnerabilityContext<'g>>, Error> {
        Ok(self
            .advisory
            .find_related(entity::advisory_vulnerability::Entity)
            .filter(entity::advisory_vulnerability::Column::VulnerabilityId.eq(identifier))
            .one(&self.graph.connection(&tx))
            .await?
            .map(|vuln| (self, vuln).into()))
    }

    #[instrument(skip(self, information, tx), err)]
    pub async fn link_to_vulnerability<TX: AsRef<Transactional>>(
        &self,
        identifier: &str,
        information: Option<AdvisoryVulnerabilityInformation>,
        tx: TX,
    ) -> Result<AdvisoryVulnerabilityContext, Error> {
        let entity = entity::advisory_vulnerability::ActiveModel {
            advisory_id: Set(self.advisory.id),
            vulnerability_id: Set(identifier.to_string()),
            title: Set(information.as_ref().and_then(|info| info.title.clone())),
            summary: Set(information.as_ref().and_then(|info| info.summary.clone())),
            description: Set(information
                .as_ref()
                .and_then(|info| info.description.clone())),
            discovery_date: Set(information.as_ref().and_then(|info| info.discovery_date)),
            release_date: Set(information.as_ref().and_then(|info| info.release_date)),
            cwes: Set(information.as_ref().and_then(|info| info.cwes.clone())),
        };

        // do an upsert, updating field on a conflict
        let entity = entity::advisory_vulnerability::Entity::insert(entity)
            .on_conflict(
                OnConflict::columns([
                    entity::advisory_vulnerability::Column::AdvisoryId,
                    entity::advisory_vulnerability::Column::VulnerabilityId,
                ])
                .update_columns([
                    entity::advisory_vulnerability::Column::Title,
                    entity::advisory_vulnerability::Column::Summary,
                    entity::advisory_vulnerability::Column::Description,
                    entity::advisory_vulnerability::Column::DiscoveryDate,
                    entity::advisory_vulnerability::Column::ReleaseDate,
                    entity::advisory_vulnerability::Column::Cwes,
                ])
                .to_owned(),
            )
            .exec_with_returning(&self.graph.connection(&tx))
            .await?;

        Ok((self, entity).into())
    }

    pub async fn vulnerabilities<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<AdvisoryVulnerabilityContext>, Error> {
        Ok(self
            .advisory
            .find_related(entity::advisory_vulnerability::Entity)
            .all(&self.graph.connection(&tx))
            .await?
            .into_iter()
            .map(|e| (self, e).into())
            .collect())
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::Transactional;
    use trustify_common::hashing::Digests;
    use trustify_entity::labels::Labels;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn ingest_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory1 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1_1"),
                (),
                Transactional::None,
            )
            .await?;

        let advisory2 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1_1"),
                (),
                Transactional::None,
            )
            .await?;

        let advisory3 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1_2"),
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
    async fn ingest_advisory_cve(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db);

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                Labels::from_one("source", "http://db.com/rhsa-ghsa-2"),
                &Digests::digest("RHSA-GHSA-1"),
                (),
                Transactional::None,
            )
            .await?;

        advisory
            .link_to_vulnerability("CVE-123", None, Transactional::None)
            .await?;
        advisory
            .link_to_vulnerability("CVE-123", None, Transactional::None)
            .await?;
        advisory
            .link_to_vulnerability("CVE-456", None, Transactional::None)
            .await?;

        let vulns = advisory.vulnerabilities(()).await?;

        assert_eq!(vulns.len(), 2);

        Ok(())
    }
}
