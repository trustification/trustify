//! Support for *versioned* package.

use crate::graph::error::Error;
use crate::graph::package::qualified_package::QualifiedPackageContext;
use crate::graph::package::PackageContext;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    RelationTrait, Set,
};
use sea_query::JoinType;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use trustify_common::db::Transactional;
use trustify_common::package::{Assertion, Claimant, PackageVulnerabilityAssertions};
use trustify_common::purl::Purl;
use trustify_entity as entity;
use trustify_entity::qualified_package::Qualifiers;

/// Live context for a package version.
#[derive(Clone)]
pub struct PackageVersionContext<'g> {
    pub(crate) package: PackageContext<'g>,
    pub(crate) package_version: entity::package_version::Model,
}

impl Debug for PackageVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version.fmt(f)
    }
}

impl<'g> From<(&PackageContext<'g>, entity::package_version::Model)> for PackageVersionContext<'g> {
    fn from(
        (package, package_version): (&PackageContext<'g>, entity::package_version::Model),
    ) -> Self {
        Self {
            package: package.clone(),
            package_version,
        }
    }
}

impl<'g> PackageVersionContext<'g> {
    pub async fn ingest_qualified_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<QualifiedPackageContext<'g>, Error> {
        if let Some(found) = self.get_qualified_package(purl.clone(), &tx).await? {
            return Ok(found);
        }

        // No appropriate qualified package, create one.
        let qualified_package = entity::qualified_package::ActiveModel {
            id: Default::default(),
            package_version_id: Set(self.package_version.id),
            qualifiers: Set(Some(Qualifiers(purl.qualifiers))),
        };

        let qualified_package = qualified_package
            .insert(&self.package.graph.connection(&tx))
            .await?;

        Ok((self, qualified_package).into())
    }

    pub async fn get_qualified_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Option<QualifiedPackageContext<'g>>, Error> {
        let found = entity::qualified_package::Entity::find()
            .filter(entity::qualified_package::Column::PackageVersionId.eq(self.package_version.id))
            .one(&self.package.graph.connection(&tx))
            .await?;

        Ok(None)
    }

    pub async fn vulnerability_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        let affected = self.affected_assertions(&tx).await?;

        let not_affected = self.not_affected_assertions(&tx).await?;

        let mut merged = PackageVulnerabilityAssertions::default();

        merged.assertions.extend_from_slice(&affected.assertions);

        merged
            .assertions
            .extend_from_slice(&not_affected.assertions);

        Ok(merged)
    }

    pub async fn affected_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        let possibly_affected = self.package.affected_assertions(tx).await?;

        let filtered = possibly_affected.filter_by_version(&self.package_version.version)?;

        Ok(filtered)
    }

    pub async fn not_affected_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        #[derive(FromQueryResult, Debug)]
        struct NotAffectedVersion {
            version: String,
            advisory_id: i32,
            identifier: String,
            location: String,
            sha256: String,
        }

        let mut not_affected_versions = entity::not_affected_package_version::Entity::find()
            .column_as(entity::package_version::Column::Version, "version")
            .column_as(entity::advisory::Column::Id, "advisory_id")
            .column_as(entity::advisory::Column::Identifier, "identifier")
            .column_as(entity::advisory::Column::Location, "location")
            .column_as(entity::advisory::Column::Sha256, "sha256")
            .join(
                JoinType::Join,
                entity::not_affected_package_version::Relation::Advisory.def(),
            )
            .join(
                JoinType::Join,
                entity::not_affected_package_version::Relation::PackageVersion.def(),
            )
            .filter(entity::package_version::Column::Id.eq(self.package_version.id))
            .into_model::<NotAffectedVersion>()
            .all(&self.package.graph.connection(&tx))
            .await?;

        let mut assertions = PackageVulnerabilityAssertions::default();

        for each in not_affected_versions {
            let vulnerability = "not-implemented".to_string();

            assertions.assertions.push(Assertion::NotAffected {
                vulnerability,
                claimant: Claimant {
                    identifier: each.identifier,
                    location: each.location,
                    sha256: each.sha256,
                },
                version: each.version,
            });
        }

        Ok(assertions)
    }

    /// Retrieve known variants of this package version.
    ///
    /// Non-mutating to the graph.
    pub async fn get_variants<TX: AsRef<Transactional>>(
        &self,
        pkg: Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        Ok(entity::qualified_package::Entity::find()
            .filter(entity::qualified_package::Column::PackageVersionId.eq(self.package_version.id))
            .all(&self.package.graph.connection(&tx))
            .await?
            .into_iter()
            .map(|base| (self, base).into())
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::graph::Graph;
    use trustify_common::db::{Database, Transactional};

    #[tokio::test]
    async fn package_version_not_affected_assertions() -> Result<(), anyhow::Error> {
        let db = Database::for_test("package_version_not_affected_assertions").await?;
        let system = Graph::new(db);

        let redhat_advisory = system
            .ingest_advisory(
                "RHSA-1",
                "http://redhat.com/rhsa-1",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let redhat_advisory_vulnerability = redhat_advisory
            .link_to_vulnerability("CVE-1", Transactional::None)
            .await?;

        redhat_advisory_vulnerability
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2".try_into()?,
                Transactional::None,
            )
            .await?;

        let ghsa_advisory = system
            .ingest_advisory(
                "GHSA-1",
                "http://ghsa.com/ghsa-1",
                "2",
                (),
                Transactional::None,
            )
            .await?;

        let ghsa_advisory_vulnerability = ghsa_advisory
            .link_to_vulnerability("CVE-1", Transactional::None)
            .await?;

        ghsa_advisory_vulnerability
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.2".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg_version = system
            .get_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.2".try_into()?,
                Transactional::None,
            )
            .await?
            .unwrap();

        let assertions = pkg_version
            .not_affected_assertions(Transactional::None)
            .await?;

        assert_eq!(assertions.assertions.len(), 1);

        Ok(())
    }
}
