//! Support for advisories.

use crate::{
    common::{Deprecation, DeprecationExt},
    graph::{advisory::advisory_vulnerability::AdvisoryVulnerabilityContext, error::Error, Graph},
};
use hex::ToHex;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, ModelTrait,
    QueryFilter, QuerySelect, RelationTrait,
};
use sea_query::{Condition, JoinType, OnConflict};
use semver::Version;
use std::fmt::{Debug, Formatter};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{
    db::{Transactional, UpdateDeprecatedAdvisory},
    hashing::Digests,
};
use trustify_entity::{self as entity, advisory, labels::Labels, source_document};
use uuid::Uuid;

pub mod advisory_vulnerability;

#[derive(Clone, Default)]
pub struct AdvisoryInformation {
    pub title: Option<String>,
    pub issuer: Option<String>,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
    pub version: Option<Version>,
}

pub struct AdvisoryVulnerabilityInformation {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub reserved_date: Option<OffsetDateTime>,
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
            || self.version.is_some()
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
        Ok(advisory::Entity::find()
            .join(JoinType::Join, advisory::Relation::SourceDocument.def())
            .filter(
                Condition::any()
                    .add(source_document::Column::Sha256.eq(digest.to_string()))
                    .add(source_document::Column::Sha384.eq(digest.to_string()))
                    .add(source_document::Column::Sha512.eq(digest.to_string())),
            )
            .one(&self.connection(&tx))
            .await?
            .map(|advisory| AdvisoryContext::new(self, advisory)))
    }

    pub async fn get_advisories<TX: AsRef<Transactional>>(
        &self,
        deprecation: Deprecation,
        tx: TX,
    ) -> Result<Vec<AdvisoryContext>, Error> {
        Ok(advisory::Entity::find()
            .with_deprecation(deprecation)
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
        let AdvisoryInformation {
            title,
            issuer,
            published,
            modified,
            withdrawn,
            version,
        } = information.into();

        if let Some(found) = self.get_advisory_by_digest(&sha256, &tx).await? {
            // we already have the exact same document.
            return Ok(found);
        }

        let organization = if let Some(issuer) = issuer {
            Some(self.ingest_organization(issuer, (), &tx).await?)
        } else {
            None
        };

        let doc_model = source_document::ActiveModel {
            id: Default::default(),
            sha256: Set(sha256),
            sha384: Set(digests.sha384.encode_hex()),
            sha512: Set(digests.sha512.encode_hex()),
            size: Set(digests.size as i64),
        };

        let doc = doc_model.insert(&self.connection(&tx)).await?;

        // insert

        let model = advisory::ActiveModel {
            id: Default::default(),
            identifier: Set(identifier),
            // we create it as not deprecated (false), as we update all documents in the next step.
            deprecated: Set(false),
            version: Set(version.map(|version| version.to_string())),
            issuer_id: Set(organization.map(|org| org.organization.id)),
            title: Set(title),
            published: Set(published),
            modified: Set(modified),
            withdrawn: Set(withdrawn),
            labels: Set(labels),
            source_document_id: Set(Some(doc.id)),
        };

        let db = self.connection(&tx);

        let result = model.insert(&db).await?;

        // update deprecation marker

        UpdateDeprecatedAdvisory::execute(&db, &result.identifier).await?;

        // done

        Ok(AdvisoryContext::new(self, result))
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
        published_at: OffsetDateTime,
        tx: TX,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.published = Set(Some(published_at));
        entity.save(&self.graph.connection(&tx)).await?;
        Ok(())
    }

    pub fn published_at(&self) -> Option<OffsetDateTime> {
        self.advisory.published
    }

    pub async fn set_modified_at<TX: AsRef<Transactional>>(
        &self,
        modified_at: OffsetDateTime,
        tx: TX,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.modified = Set(Some(modified_at));
        entity.save(&self.graph.connection(&tx)).await?;
        Ok(())
    }

    pub fn modified_at(&self) -> Option<OffsetDateTime> {
        self.advisory.modified
    }

    pub async fn set_withdrawn_at<TX: AsRef<Transactional>>(
        &self,
        withdrawn_at: OffsetDateTime,
        tx: TX,
    ) -> Result<(), Error> {
        let mut entity = self.advisory.clone().into_active_model();
        entity.withdrawn = Set(Some(withdrawn_at));
        entity.save(&self.graph.connection(&tx)).await?;
        Ok(())
    }

    pub fn withdrawn_at(&self) -> Option<OffsetDateTime> {
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
            reserved_date: Set(information.as_ref().and_then(|info| info.reserved_date)),
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
    use crate::common::Deprecation;
    use crate::graph::advisory::AdvisoryInformation;
    use crate::graph::Graph;
    use test_context::test_context;
    use test_log::test;
    use time::macros::datetime;
    use time::OffsetDateTime;
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

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn deprecation(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        struct Info(OffsetDateTime);

        impl From<Info> for AdvisoryInformation {
            fn from(value: Info) -> Self {
                AdvisoryInformation {
                    title: None,
                    issuer: None,
                    published: None,
                    modified: Some(value.0),
                    withdrawn: None,
                    version: None,
                }
            }
        }

        let db = ctx.db;
        let system = Graph::new(db);

        let a1 = system
            .ingest_advisory(
                "RHSA",
                (),
                &Digests::digest("RHSA-1"),
                Info(datetime!(2024-01-02 00:00:00 UTC)),
                Transactional::None,
            )
            .await?
            .advisory
            .id;

        let a2 = system
            .ingest_advisory(
                "RHSA",
                (),
                &Digests::digest("RHSA-2"),
                Info(datetime!(2024-01-03 00:00:00 UTC)),
                Transactional::None,
            )
            .await?
            .advisory
            .id;

        let a3 = system
            .ingest_advisory(
                "RHSA",
                (),
                &Digests::digest("RHSA-3"),
                Info(datetime!(2024-01-01 00:00:00 UTC)),
                Transactional::None,
            )
            .await?
            .advisory
            .id;

        let mut advs = system.get_advisories(Deprecation::Consider, ()).await?;
        advs.sort_unstable_by(|a, b| a.advisory.modified.cmp(&b.advisory.modified));
        let deps = advs
            .iter()
            .map(|adv| (adv.advisory.id, adv.advisory.deprecated))
            .collect::<Vec<_>>();

        // a3 must come first, it was ingested last, but its timestamp is the earliest one. Also,
        // it must be deprecated, despite being ingested last.
        // a1 is ingested first but deprecated when ingesting a2.
        // a2 is the "most recent" one, and most not be deprecated.

        assert_eq!(deps, vec![(a3, true), (a1, true), (a2, false)]);

        Ok(())
    }
}
