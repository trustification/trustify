use crate::db::Transactional;
use crate::system::advisory_cve::AdvisoryCveContext;
use crate::system::affected_package_version_range::AffectedPackageVersionRangeContext;
use crate::system::cve::CveContext;
use crate::system::error::Error;
use crate::system::fixed_package_version::FixedPackageVersionContext;
use crate::system::{InnerSystem};
use huevos_common::purl::Purl;
use huevos_entity::{advisory, advisory_cve, affected_package_version_range, cve, fixed_package_version, not_affected_package_version, package_version_range};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryFilter};
use sea_orm::{ColumnTrait, QuerySelect, RelationTrait};
use sea_query::{Condition, JoinType};
use std::fmt::{Debug, Formatter};
use crate::system::not_affected_package_version::NotAffectedPackageVersion;

impl InnerSystem {
    pub async fn get_advisory(
        &self,
        identifier: &str,
        location: &str,
        sha256: &str,
    ) -> Result<Option<AdvisoryContext>, Error> {
        Ok(advisory::Entity::find()
            .filter(Condition::all().add(advisory::Column::Identifier.eq(identifier)))
            .filter(Condition::all().add(advisory::Column::Location.eq(location)))
            .filter(Condition::all().add(advisory::Column::Sha256.eq(sha256.to_string())))
            .one(&self.db)
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    pub async fn ingest_advisory(
        &self,
        identifer: &str,
        location: &str,
        sha256: &str,
        tx: Transactional<'_>,
    ) -> Result<AdvisoryContext, Error> {
        if let Some(found) = self.get_advisory(identifer, location, sha256).await? {
            return Ok(found);
        }

        let model = advisory::ActiveModel {
            identifier: Set(identifer.to_string()),
            location: Set(location.to_string()),
            sha256: Set(sha256.to_string()),
            ..Default::default()
        };

        Ok((self, model.insert(&self.db).await?).into())
    }
}

#[derive(Clone)]
pub struct AdvisoryContext {
    system: InnerSystem,
    advisory: advisory::Model,
}

impl PartialEq for AdvisoryContext {
    fn eq(&self, other: &Self) -> bool {
        self.advisory.eq(&other.advisory)
    }
}

impl Debug for AdvisoryContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.advisory.fmt(f)
    }
}

impl From<(&InnerSystem, advisory::Model)> for AdvisoryContext {
    fn from((system, advisory): (&InnerSystem, advisory::Model)) -> Self {
        Self {
            system: system.clone(),
            advisory,
        }
    }
}

impl AdvisoryContext {
    pub async fn get_cve(
        &self,
        identifier: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<AdvisoryCveContext>, Error> {
        Ok(cve::Entity::find()
            .join(JoinType::Join, advisory_cve::Relation::Cve.def().rev())
            .filter(advisory_cve::Column::AdvisoryId.eq(self.advisory.id))
            .filter(cve::Column::Identifier.eq(identifier))
            .one(&self.system.connection(tx))
            .await?
            .map(|cve| (self, cve).into()))
    }

    pub async fn ingest_cve(
        &self,
        identifier: &str,
        tx: Transactional<'_>,
    ) -> Result<AdvisoryCveContext, Error> {
        if let Some(found) = self.get_cve(identifier, tx.clone()).await? {
            return Ok(found);
        }

        let cve = self.system.ingest_cve(identifier, tx).await?;

        let entity = advisory_cve::ActiveModel {
            advisory_id: Set(self.advisory.id),
            cve_id: Set(cve.cve.id),
        };

        entity.insert(&self.system.connection(tx)).await?;

        Ok((self, cve.cve).into())
    }

    pub async fn get_fixed_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<FixedPackageVersionContext>, Error> {
        let purl = pkg.into();

        if let Some(package_version) = self.system.get_package_version(purl, tx).await? {
            Ok(fixed_package_version::Entity::find()
                .filter(fixed_package_version::Column::AdvisoryId.eq(self.advisory.id))
                .filter(
                    fixed_package_version::Column::PackageVersionId
                        .eq(package_version.package_version.id),
                )
                .one(&self.system.connection(tx))
                .await?
                .map(|affected| (self, affected).into()))
        } else {
            Ok(None)
        }
    }

    pub async fn get_not_affected_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<NotAffectedPackageVersion>, Error> {
        let purl = pkg.into();

        if let Some(package_version) = self.system.get_package_version(purl, tx).await? {
            Ok(not_affected_package_version::Entity::find()
                .filter(not_affected_package_version::Column::AdvisoryId.eq(self.advisory.id))
                .filter(
                    not_affected_package_version::Column::PackageVersionId
                        .eq(package_version.package_version.id),
                )
                .one(&self.system.connection(tx))
                .await?
                .map(|not_affected_package_version| (self, not_affected_package_version).into()))
        } else {
            Ok(None)
        }
    }


    pub async fn get_affected_package_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<AffectedPackageVersionRangeContext>, Error> {
        let purl = pkg.into();

        if let Some(package_version_range) = self
            .system
            .get_package_version_range(purl.clone(), start, end, tx)
            .await?
        {
            Ok(affected_package_version_range::Entity::find()
                .filter(affected_package_version_range::Column::AdvisoryId.eq(self.advisory.id))
                .filter(
                    affected_package_version_range::Column::PackageVersionRangeId
                        .eq(package_version_range.package_version_range.id),
                )
                .one(&self.system.connection(tx))
                .await?
                .map(|affected| (self, affected).into()))
        } else {
            Ok(None)
        }
    }

    pub async fn ingest_not_affected_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<NotAffectedPackageVersion, Error> {
        let purl = pkg.into();
        if let Some(found) = self.get_not_affected_package_version(purl.clone(), tx).await? {
            return Ok(found);
        }

        let package_version = self.system.ingest_package_version(purl, tx).await?;

        let entity = not_affected_package_version::ActiveModel {
            id: Default::default(),
            advisory_id: Set(self.advisory.id),
            package_version_id: Set(package_version.package_version.id),
        };

        Ok((self, entity.insert(&self.system.connection(tx)).await?).into())
    }

    pub async fn ingest_fixed_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<FixedPackageVersionContext, Error> {
        let purl = pkg.into();
        if let Some(found) = self.get_fixed_package_version(purl.clone(), tx).await? {
            return Ok(found);
        }

        let package_version = self.system.ingest_package_version(purl, tx).await?;

        let entity = fixed_package_version::ActiveModel {
            id: Default::default(),
            advisory_id: Set(self.advisory.id),
            package_version_id: Set(package_version.package_version.id),
        };

        Ok((self, entity.insert(&self.system.connection(tx)).await?).into())
    }

    pub async fn ingest_affected_package_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<AffectedPackageVersionRangeContext, Error> {
        let purl = pkg.into();
        if let Some(found) = self
            .get_affected_package_range(purl.clone(), start, end, tx)
            .await?
        {
            return Ok(found);
        }

        let package_version_range = self
            .system
            .ingest_package_version_range(purl, start, end, tx)
            .await?;

        let entity = affected_package_version_range::ActiveModel {
            id: Default::default(),
            advisory_id: Set(self.advisory.id),
            package_version_range_id: Set(package_version_range.package_version_range.id),
        };

        Ok((self, entity.insert(&self.system.connection(tx)).await?).into())
    }
}

#[cfg(test)]
mod test {
    use crate::db::Transactional;
    use crate::system::InnerSystem;

    #[tokio::test]
    async fn ingest_advisories() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_advisories").await?;

        let advisory1 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let advisory2 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let advisory3 = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "89",
                Transactional::None,
            )
            .await?;

        assert_eq!(advisory1.advisory.id, advisory2.advisory.id);
        assert_ne!(advisory1.advisory.id, advisory3.advisory.id);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_affected_package_version_range() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_affected_package_version_range").await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let affected1 = advisory
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let affected2 = advisory
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let affected3 = advisory
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-addons",
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

    #[tokio::test]
    async fn ingest_fixed_package_version() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_fixed_package_version").await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let affected = advisory
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let fixed1 = advisory
            .ingest_fixed_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.0",
                Transactional::None,
            )
            .await?;

        let fixed2 = advisory
            .ingest_fixed_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.0",
                Transactional::None,
            )
            .await?;

        let fixed3 = advisory
            .ingest_fixed_package_version(
                "pkg://maven/io.quarkus/quarkus-addons@1.2.0",
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

    #[tokio::test]
    async fn ingest_advisory_cve() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_advisory_cve").await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-GHSA-1",
                "http://db.com/rhsa-ghsa-2",
                "2",
                Transactional::None,
            )
            .await?;

        let cve1 = advisory.ingest_cve("CVE-123", Transactional::None).await?;
        let cve2 = advisory.ingest_cve("CVE-123", Transactional::None).await?;
        let cve3 = advisory.ingest_cve("CVE-456", Transactional::None).await?;

        assert_eq!(cve1.cve.id, cve2.cve.id);
        assert_ne!(cve1.cve.id, cve3.cve.id);

        Ok(())
    }
}
