use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::package::qualified_package::QualifiedPackageContext;
use crate::system::package::PackageContext;
use huevos_common::package::{Assertion, Claimant, PackageVulnerabilityAssertions};
use huevos_common::purl::Purl;
use huevos_entity as entity;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    RelationTrait, Set,
};
use sea_query::JoinType;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct PackageVersionContext {
    pub(crate) package: PackageContext,
    pub(crate) package_version: entity::package_version::Model,
}

impl Debug for PackageVersionContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version.fmt(f)
    }
}

impl From<(&PackageContext, entity::package_version::Model)> for PackageVersionContext {
    fn from((package, package_version): (&PackageContext, entity::package_version::Model)) -> Self {
        Self {
            package: package.clone(),
            package_version,
        }
    }
}

impl PackageVersionContext {
    pub async fn ingest_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        mut tx: Transactional<'_>,
    ) -> Result<QualifiedPackageContext, Error> {
        let purl = pkg.into();

        if let Some(found) = self.get_qualified_package(purl.clone(), tx).await? {
            return Ok(found);
        }

        // No appropriate qualified package, create one.
        let qualified_package = entity::qualified_package::ActiveModel {
            id: Default::default(),
            package_version_id: Set(self.package_version.package_id),
        };

        let qualified_package = qualified_package
            .insert(&self.package.system.connection(tx))
            .await?;

        for (k, v) in &purl.qualifiers {
            let qualifier = entity::package_qualifier::ActiveModel {
                id: Default::default(),
                qualified_package_id: Set(qualified_package.id),
                key: Set(k.clone()),
                value: Set(v.clone()),
            };

            qualifier
                .insert(&self.package.system.connection(tx))
                .await?;
        }

        Ok((self, qualified_package, purl.qualifiers.clone()).into())
    }

    pub async fn get_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        let purl = pkg.into();
        let found = entity::qualified_package::Entity::find()
            .filter(entity::qualified_package::Column::PackageVersionId.eq(self.package_version.id))
            .find_with_related(entity::package_qualifier::Entity)
            .all(&self.package.system.connection(tx))
            .await?;

        for (qualified_package, qualifiers) in found {
            let qualifiers_map = qualifiers
                .iter()
                .map(|qualifier| (qualifier.key.clone(), qualifier.value.clone()))
                .collect::<HashMap<_, _>>();

            if purl.qualifiers == qualifiers_map {
                return Ok(Some((self, qualified_package, qualifiers_map).into()));
            }
        }

        Ok(None)
    }

    pub async fn vulnerability_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        let affected = self.affected_assertions(tx).await?;

        let not_affected = self.not_affected_assertions(tx).await?;

        let mut merged = PackageVulnerabilityAssertions::default();

        merged.assertions.extend_from_slice(&affected.assertions);

        merged
            .assertions
            .extend_from_slice(&not_affected.assertions);

        Ok(merged)
    }

    pub async fn affected_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        let possibly_affected = self.package.affected_assertions(tx).await?;

        let filtered = possibly_affected.filter_by_version(&self.package_version.version)?;

        Ok(filtered)
    }

    pub async fn not_affected_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        #[derive(FromQueryResult, Debug)]
        struct NotAffectedVersion {
            version: String,
            identifier: String,
            location: String,
            sha256: String,
        }

        let mut not_affected_versions = entity::not_affected_package_version::Entity::find()
            .column_as(entity::package_version::Column::Version, "version")
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
            .all(&self.package.system.connection(tx))
            .await?;

        let assertions = PackageVulnerabilityAssertions {
            assertions: not_affected_versions
                .drain(0..)
                .map(|each| Assertion::NotAffected {
                    claimant: Claimant {
                        identifier: each.identifier,
                        location: each.location,
                        sha256: each.sha256,
                    },
                    version: each.version,
                })
                .collect(),
        };

        Ok(assertions)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;

    #[tokio::test]
    async fn package_version_not_affected_assertions() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("package_version_not_affected_assertions").await?;

        let redhat_advisory = system
            .ingest_advisory(
                "RHSA-1",
                "http://redhat.com/rhsa-1",
                "2",
                Transactional::None,
            )
            .await?;

        redhat_advisory
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2",
                Transactional::None,
            )
            .await?;

        let ghsa_advisory = system
            .ingest_advisory("GHSA-1", "http://ghsa.com/ghsa-1", "2", Transactional::None)
            .await?;

        ghsa_advisory
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.2",
                Transactional::None,
            )
            .await?;

        let pkg_version = system
            .get_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.2",
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
