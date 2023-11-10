use huevos_common::package::{Assertion, Claimant, PackageVulnerabilityAssertions};
use huevos_common::purl::{Purl, PurlErr};
use huevos_entity as entity;
use package_version::PackageVersionContext;
use qualified_package::QualifiedPackageContext;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, ModelTrait,
    QueryFilter, QuerySelect, Set,
};
use sea_orm::{RelationTrait, TransactionTrait};
use sea_query::JoinType;
use std::fmt::{Debug, Formatter};

use crate::db::Transactional;
use crate::system::error::Error;
use crate::system::InnerSystem;

pub mod package_version;
pub mod package_version_range;
pub mod qualified_package;

impl InnerSystem {
    pub async fn ingest_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<QualifiedPackageContext, Error> {
        let purl = pkg.into();
        let package_version = self.ingest_package_version(purl.clone(), tx).await?;

        package_version
            .ingest_qualified_package(purl.clone(), tx)
            .await
    }

    pub async fn ingest_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionContext, Error> {
        let pkg = pkg.into();
        let package = self.ingest_package(pkg.clone(), tx).await?;

        package.ingest_package_version(pkg.clone(), tx).await
    }

    pub async fn ingest_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionRangeContext, Error> {
        let pkg = pkg.into();
        let package = self.ingest_package(pkg.clone(), tx).await?;

        package
            .ingest_package_version_range(pkg.clone(), start, end, tx)
            .await
    }

    pub async fn ingest_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageContext, Error> {
        let purl = pkg.into();

        if let Some(found) = self.get_package(purl.clone(), tx).await? {
            Ok(found)
        } else {
            let model = entity::package::ActiveModel {
                id: Default::default(),
                r#type: Set(purl.ty.clone()),
                namespace: Set(purl.namespace.clone()),
                name: Set(purl.name.clone()),
            };

            Ok((self, model.insert(&self.connection(tx)).await?).into())
        }
    }

    pub async fn get_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        let purl = pkg.into();
        if let Some(package_version) = self.get_package_version(purl.clone(), tx).await? {
            package_version.get_qualified_package(purl, tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionContext>, Error> {
        let purl = pkg.into();
        if let Some(pkg) = self.get_package(purl.clone(), tx).await? {
            pkg.get_package_version(purl, tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionRangeContext>, Error> {
        let purl = pkg.into();
        if let Some(pkg) = self.get_package(purl.clone(), tx).await? {
            pkg.get_package_version_range(purl, start, end, tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageContext>, Error> {
        let purl = pkg.into();
        Ok(entity::package::Entity::find()
            .filter(entity::package::Column::Type.eq(purl.ty.clone()))
            .filter(entity::package::Column::Namespace.eq(purl.namespace.clone()))
            .filter(entity::package::Column::Name.eq(purl.name.clone()))
            .one(&self.connection(tx))
            .await?
            .map(|package| (self, package).into()))
    }
}

#[derive(Clone)]
pub struct PackageContext {
    pub(crate) system: InnerSystem,
    pub(crate) package: entity::package::Model,
}

impl Debug for PackageContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package.fmt(f)
    }
}

impl From<(&InnerSystem, entity::package::Model)> for PackageContext {
    fn from((system, package): (&InnerSystem, entity::package::Model)) -> Self {
        Self {
            system: system.clone(),
            package,
        }
    }
}

impl PackageContext {
    pub async fn ingest_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionRangeContext, Error> {
        let purl = pkg.into();
        if let Some(found) = self.get_package_version_range(purl, start, end, tx).await? {
            Ok(found)
        } else {
            let entity = entity::package_version_range::ActiveModel {
                id: Default::default(),
                package_id: Set(self.package.id),
                start: Set(start.to_string()),
                end: Set(end.to_string()),
            };

            Ok((self, entity.insert(&self.system.connection(tx)).await?).into())
        }
    }

    pub async fn get_package_version_range<P: Into<Purl>>(
        &self,
        pkg: P,
        start: &str,
        end: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionRangeContext>, Error> {
        let purl = pkg.into();

        Ok(entity::package_version_range::Entity::find()
            .filter(entity::package_version_range::Column::PackageId.eq(self.package.id))
            .filter(entity::package_version_range::Column::Start.eq(start.to_string()))
            .filter(entity::package_version_range::Column::End.eq(end.to_string()))
            .one(&self.system.connection(tx))
            .await?
            .map(|package_version_range| (self, package_version_range).into()))
    }

    pub async fn ingest_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionContext, Error> {
        let purl = pkg.into();

        if let Some(version) = &purl.version {
            if let Some(found) = self.get_package_version(purl.clone(), tx).await? {
                Ok(found)
            } else {
                let model = entity::package_version::ActiveModel {
                    id: Default::default(),
                    package_id: Set(self.package.id),
                    version: Set(version.clone()),
                };

                Ok((self, model.insert(&self.system.connection(tx)).await?).into())
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion))
        }
    }

    pub async fn get_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionContext>, Error> {
        let purl = pkg.into();
        if let Some(package_version) = entity::package_version::Entity::find()
            .join(
                JoinType::Join,
                entity::package_version::Relation::Package.def(),
            )
            .filter(entity::package::Column::Id.eq(self.package.id))
            .filter(entity::package_version::Column::Version.eq(purl.version.clone()))
            .one(&self.system.connection(tx))
            .await?
        {
            Ok(Some((self, package_version).into()))
        } else {
            Ok(None)
        }
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
        #[derive(FromQueryResult, Debug)]
        struct AffectedVersion {
            start: String,
            end: String,
            identifier: String,
            location: String,
            sha256: String,
        }

        let mut affected_version_ranges = entity::affected_package_version_range::Entity::find()
            .column_as(entity::package_version_range::Column::Start, "start")
            .column_as(entity::package_version_range::Column::End, "end")
            .column_as(entity::advisory::Column::Identifier, "identifier")
            .column_as(entity::advisory::Column::Location, "location")
            .column_as(entity::advisory::Column::Sha256, "sha256")
            .join(
                JoinType::Join,
                entity::affected_package_version_range::Relation::PackageVersionRange.def(),
            )
            .join(
                JoinType::Join,
                entity::package_version_range::Relation::Package.def(),
            )
            .join(
                JoinType::Join,
                entity::affected_package_version_range::Relation::Advisory.def(),
            )
            .filter(entity::package::Column::Id.eq(self.package.id))
            .into_model::<AffectedVersion>()
            .all(&self.system.connection(tx))
            .await?;

        let assertions = PackageVulnerabilityAssertions {
            assertions: affected_version_ranges
                .drain(0..)
                .map(|each| Assertion::Affected {
                    claimant: Claimant {
                        identifier: each.identifier,
                        location: each.location,
                        sha256: each.sha256,
                    },
                    start_version: each.start,
                    end_version: each.end,
                })
                .collect(),
        };

        Ok(assertions)
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
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .into_model::<NotAffectedVersion>()
            .all(&self.system.connection(tx))
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

#[derive(Clone)]
pub struct PackageVersionRangeContext {
    pub(crate) package: PackageContext,
    pub(crate) package_version_range: entity::package_version_range::Model,
}

impl Debug for PackageVersionRangeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package_version_range.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;
    use huevos_common::purl::Purl;

    #[tokio::test]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_packages").await?;

        let pkg1 = system
            .ingest_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
            .await?;

        let pkg2 = system
            .ingest_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
            .await?;

        let pkg3 = system
            .ingest_package("pkg://maven/io.quarkus/quarkus-addons", Transactional::None)
            .await?;

        assert_eq!(pkg1.package.id, pkg2.package.id,);

        assert_ne!(pkg1.package.id, pkg3.package.id);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_versions_missing_version() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_package_versions_missing_version").await?;

        let result = system
            .ingest_package_version("pkg://maven/io.quarkus/quarkus-addons", Transactional::None)
            .await;

        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_versions() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_package_versions").await?;

        let pkg1 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@4.5.6",
                Transactional::None,
            )
            .await?;

        assert_eq!(pkg1.package.package.id, pkg2.package.package.id);
        assert_eq!(pkg1.package_version.id, pkg2.package_version.id);

        assert_eq!(pkg1.package.package.id, pkg3.package.package.id);
        assert_ne!(pkg1.package_version.id, pkg3.package_version.id);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_qualified_packages() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_qualified_packages").await?;

        let pkg1 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
                Transactional::None,
            )
            .await?;

        let pkg4 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
                Transactional::None,
            )
            .await?;

        assert_eq!(pkg1.qualified_package.id, pkg2.qualified_package.id);
        assert_eq!(pkg3.qualified_package.id, pkg4.qualified_package.id);

        assert_ne!(pkg1.qualified_package.id, pkg3.qualified_package.id);

        assert_eq!(
            "pkg://maven/io.quarkus/quarkus-core@1.2.3",
            Purl::from(pkg1).to_string().as_str()
        );
        assert_eq!(
            "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
            Purl::from(pkg3).to_string().as_str()
        );

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_version_ranges() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_package_version_ranges").await?;

        let range1 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let range2 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-core",
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let range3 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-addons",
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        assert_eq!(
            range1.package_version_range.id,
            range2.package_version_range.id
        );
        assert_ne!(
            range1.package_version_range.id,
            range3.package_version_range.id
        );

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use crate::db::Transactional;
        use crate::system::InnerSystem;

        #[tokio::test]
        async fn package_affected_assertions() -> Result<(), anyhow::Error> {
            /*
            env_logger::builder()
                .filter_level(log::LevelFilter::Info)
                .is_test(true)
                .init();

             */

            let system = InnerSystem::for_test("package_affected_assertions").await?;

            let redhat_advisory = system
                .ingest_advisory(
                    "RHSA-1",
                    "http://redhat.com/rhsa-1",
                    "2",
                    Transactional::None,
                )
                .await?;

            redhat_advisory
                .ingest_affected_package_range(
                    "pkg://maven/io.quarkus/quarkus-core",
                    "1.0.2",
                    "1.2.0",
                    Transactional::None,
                )
                .await?;

            redhat_advisory
                .ingest_affected_package_range(
                    "pkg://maven/io.quarkus/quarkus-addons",
                    "1.0.2",
                    "1.2.0",
                    Transactional::None,
                )
                .await?;

            let ghsa_advisory = system
                .ingest_advisory("GHSA-1", "http://ghsa.com/ghsa-1", "2", Transactional::None)
                .await?;

            ghsa_advisory
                .ingest_affected_package_range(
                    "pkg://maven/io.quarkus/quarkus-core",
                    "1.0.2",
                    "1.2.0",
                    Transactional::None,
                )
                .await?;

            let pkg_core = system
                .get_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
                .await?
                .unwrap();

            let assertions = pkg_core.affected_assertions(Transactional::None).await?;

            assert_eq!(assertions.assertions.len(), 2);

            assert!(assertions
                .affected_claimants()
                .iter()
                .any(|e| e.identifier == "RHSA-1"));
            assert!(assertions
                .affected_claimants()
                .iter()
                .any(|e| e.identifier == "GHSA-1"));

            let pkg_addons = system
                .get_package("pkg://maven/io.quarkus/quarkus-addons", Transactional::None)
                .await?
                .unwrap();

            let assertions = pkg_addons.affected_assertions(Transactional::None).await?;

            assert_eq!(assertions.assertions.len(), 1);
            assert!(assertions
                .affected_claimants()
                .iter()
                .any(|e| e.identifier == "RHSA-1"));

            Ok(())
        }
    }
}

#[tokio::test]
async fn package_not_affected_assertions() -> Result<(), anyhow::Error> {
    let system = InnerSystem::for_test("package_not_affected_assertions").await?;

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

    let pkg = system
        .get_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
        .await?
        .unwrap();

    let assertions = pkg.not_affected_assertions(Transactional::None).await?;

    assert_eq!(assertions.assertions.len(), 2);

    Ok(())
}

#[tokio::test]
async fn package_vulnerability_assertions() -> Result<(), anyhow::Error> {
    let system = InnerSystem::for_test("package_vulnerability_assertions").await?;

    let redhat_advisory = system
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/rhsa-1",
            "2",
            Transactional::None,
        )
        .await?;

    redhat_advisory
        .ingest_affected_package_range(
            "pkg://maven/io.quarkus/quarkus-core",
            "1.1",
            "1.3",
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

    let pkg = system
        .get_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
        .await?
        .unwrap();

    let assertions = pkg.vulnerability_assertions(Transactional::None).await?;

    assert_eq!(assertions.assertions.len(), 3);

    Ok(())
}

/*
pub(crate) fn packages_to_purls(
    packages: Vec<(
        huevos_entity::package::Model,
        Vec<huevos_entity::package_qualifier::Model>,
    )>,
) -> Result<Vec<Purl>, anyhow::Error> {
    let mut purls = Vec::new();

    for (base, qualifiers) in &packages {
        purls.push(package_to_purl(base.clone(), qualifiers.clone())?);
    }

    Ok(purls)
}

 */

/*
pub(crate) fn package_to_purl(
    base: huevos_entity::package::Model,
    qualifiers: Vec<huevos_entity::package_qualifier::Model>,
) -> Result<Purl, anyhow::Error> {
    let mut purl = PackageUrl::new(base.package_type.clone(), base.package_name.clone())?;

    //purl.with_version(base.version.clone());

    if let Some(namespace) = &base.package_namespace {
        purl.with_namespace(namespace.clone());
    }

    for qualifier in qualifiers {
        purl.add_qualifier(qualifier.key.clone(), qualifier.value.clone())?;
    }

    Ok(purl.into())
}


 */
