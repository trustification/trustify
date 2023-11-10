use crate::db::Transactional;
use crate::system::advisory::AdvisoryContext;
use crate::system::error::Error;
use crate::system::InnerSystem;
use huevos_common::package::PackageVulnerabilityAssertions;
use huevos_entity::cve::Model;
use huevos_entity::{advisory, advisory_cve, cve};
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, RelationTrait,
};
use sea_query::JoinType;
use std::fmt::{Debug, Formatter};

impl InnerSystem {
    pub async fn ingest_cve(
        &self,
        identifier: &str,
        tx: Transactional<'_>,
    ) -> Result<CveContext, Error> {
        if let Some(found) = self.get_cve(identifier, tx).await? {
            Ok(found)
        } else {
            let entity = cve::ActiveModel {
                id: Default::default(),
                identifier: Set(identifier.to_string()),
            };

            Ok((self, entity.insert(&self.connection(tx)).await?).into())
        }
    }

    pub async fn get_cve(
        &self,
        identifier: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<CveContext>, Error> {
        Ok(cve::Entity::find()
            .filter(cve::Column::Identifier.eq(identifier))
            .one(&self.connection(tx))
            .await?
            .map(|cve| (self, cve).into()))
    }
}

#[derive(Clone)]
pub struct CveContext {
    pub(crate) system: InnerSystem,
    pub(crate) cve: cve::Model,
}

impl Debug for CveContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.cve.fmt(f)
    }
}

impl From<(&InnerSystem, cve::Model)> for CveContext {
    fn from((system, cve): (&InnerSystem, Model)) -> Self {
        Self {
            system: system.clone(),
            cve,
        }
    }
}

impl CveContext {
    pub async fn advisories(&self, tx: Transactional<'_>) -> Result<Vec<AdvisoryContext>, Error> {
        Ok(advisory::Entity::find()
            .join(JoinType::Join, advisory_cve::Relation::Advisory.def().rev())
            .filter(advisory_cve::Column::CveId.eq(self.cve.id))
            .all(&self.system.connection(tx))
            .await?
            .drain(0..)
            .map(|advisory| (&self.system, advisory).into())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;

    #[tokio::test]
    async fn ingest_cves() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_cve").await?;

        let cve1 = system.ingest_cve("CVE-123", Transactional::None).await?;
        let cve2 = system.ingest_cve("CVE-123", Transactional::None).await?;
        let cve3 = system.ingest_cve("CVE-456", Transactional::None).await?;

        assert_eq!(cve1.cve.id, cve2.cve.id);
        assert_ne!(cve1.cve.id, cve3.cve.id);

        let not_found = system.get_cve("CVE-NOT_FOUND", Transactional::None).await?;

        assert!(not_found.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn get_advisories_from_cve() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("get_advisories_from_cve").await?;

        let advisory1 = system
            .ingest_advisory("GHSA-1", "http://ghsa.io/GHSA-1", "7", Transactional::None)
            .await?;

        let advisory2 = system
            .ingest_advisory("RHSA-1", "http://rhsa.io/RHSA-1", "8", Transactional::None)
            .await?;

        let advisory3 = system
            .ingest_advisory("SNYK-1", "http://snyk.io/SNYK-1", "9", Transactional::None)
            .await?;

        advisory1
            .ingest_cve("CVE-8675309", Transactional::None)
            .await?;

        advisory2
            .ingest_cve("CVE-8675309", Transactional::None)
            .await?;

        let cve = system.get_cve("CVE-8675309", Transactional::None).await?;

        assert!(cve.is_some());

        let cve = cve.unwrap();

        let linked_advisories = cve.advisories(Transactional::None).await?;

        assert_eq!(2, linked_advisories.len());

        assert!(linked_advisories.contains(&advisory1));
        assert!(linked_advisories.contains(&advisory2));

        Ok(())
    }
}
