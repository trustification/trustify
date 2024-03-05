//! Support for packages.

use trustify_common::package::{Assertion, Claimant, PackageVulnerabilityAssertions};
use trustify_common::purl::{Purl, PurlErr};
use trustify_entity as entity;
use package_version::PackageVersionContext;
use package_version_range::PackageVersionRangeContext;
use qualified_package::QualifiedPackageContext;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityOrSelect, EntityTrait, FromQueryResult,
    ModelTrait, PaginatorTrait, QueryFilter, QuerySelect, QueryTrait, Set,
};
use sea_orm::{RelationTrait, TransactionTrait};
use sea_query::{JoinType, SelectStatement, UnionType};
use std::fmt::{Debug, Formatter};

use crate::db::{Paginated, PaginatedResults, Transactional};
use crate::system::advisory::AdvisoryContext;
use crate::system::error::Error;
use crate::system::InnerSystem;

pub mod package_version;
pub mod package_version_range;
pub mod qualified_package;

impl InnerSystem {
    /// Ensure the system knows about and contains a record for a *fully-qualified* package.
    ///
    /// This method will ensure the versioned package being referenced is also ingested.
    ///
    /// The `pkg` parameter does not necessarily require the presence of qualifiers, but
    /// is assumed to be *complete*.
    pub async fn ingest_qualified_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<QualifiedPackageContext, Error> {
        let purl = pkg.into();
        if let Some(found) = self.get_qualified_package(purl.clone(), tx).await? {
            return Ok(found);
        }

        let package_version = self.ingest_package_version(purl.clone(), tx).await?;

        package_version.ingest_qualified_package(purl, tx).await
    }

    /// Ensure the system knows about and contains a record for a *versioned* package.
    ///
    /// This method will ensure the package being referenced is also ingested.
    pub async fn ingest_package_version<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<PackageVersionContext, Error> {
        let pkg = pkg.into();
        if let Some(found) = self.get_package_version(pkg.clone(), tx).await? {
            return Ok(found);
        }
        let package = self.ingest_package(pkg.clone(), tx).await?;

        package.ingest_package_version(pkg.clone(), tx).await
    }

    /// Ensure the system knows about and contains a record for a *versioned range* of a package.
    ///
    /// This method will ensure the package being referenced is also ingested.
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

    /// Ensure the system knows about and contains a record for a *versionless* package.
    ///
    /// This method will ensure the package being referenced is also ingested.
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

    /// Retrieve a *fully-qualified* package entry, if it exists.
    ///
    /// Non-mutating to the system.
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

    pub(crate) async fn get_qualified_package_by_id(
        &self,
        id: i32,
        tx: Transactional<'_>,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        let mut found = entity::qualified_package::Entity::find_by_id(id)
            .find_with_related(entity::package_qualifier::Entity)
            .all(&self.connection(tx))
            .await?;

        if !found.is_empty() {
            let (qualified_package, ref mut qualifiers) = &mut found[0];

            let qualifiers = qualifiers
                .drain(0..)
                .map(|qualifier| (qualifier.key, qualifier.value))
                .collect();

            if let Some(package_version) = self
                .get_package_version_by_id(qualified_package.package_version_id, tx)
                .await?
            {
                Ok(Some(
                    (&package_version, qualified_package.clone(), qualifiers).into(),
                ))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_qualified_packages_by_query(
        &self,
        query: SelectStatement,
        tx: Transactional<'_>,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let mut found = entity::qualified_package::Entity::find()
            .filter(entity::qualified_package::Column::Id.in_subquery(query))
            .find_with_related(entity::package_qualifier::Entity)
            .all(&self.connection(tx))
            .await?;

        let mut package_versions = Vec::new();

        for (base, qualifiers) in &found {
            if let Some(package_version) = self
                .get_package_version_by_id(base.package_version_id, tx)
                .await?
            {
                let qualifiers = qualifiers
                    .iter()
                    .map(|qualifier| (qualifier.key.clone(), qualifier.value.clone()))
                    .collect();

                let qualified_package = (&package_version, base.clone(), qualifiers).into();
                package_versions.push(qualified_package);
            }
        }

        Ok(package_versions)
    }

    /// Retrieve a *versioned* package entry, if it exists.
    ///
    /// Non-mutating to the system.
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

    pub(crate) async fn get_package_version_by_id(
        &self,
        id: i32,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageVersionContext>, Error> {
        if let Some(package_version) = entity::package_version::Entity::find_by_id(id)
            .one(&self.connection(tx))
            .await?
        {
            if let Some(package) = self
                .get_package_by_id(package_version.package_id, tx)
                .await?
            {
                Ok(Some((&package, package_version).into()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Retrieve a *version range* of a package entry, if it exists.
    ///
    /// Non-mutating to the system.
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

    /// Retrieve a *versionless* package entry, if it exists.
    ///
    /// Non-mutating to the system.
    pub async fn get_package<P: Into<Purl>>(
        &self,
        pkg: P,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageContext>, Error> {
        let purl = pkg.into();
        Ok(entity::package::Entity::find()
            .filter(entity::package::Column::Type.eq(purl.ty.clone()))
            .filter(if let Some(ns) = purl.namespace {
                entity::package::Column::Namespace.eq(ns)
            } else {
                entity::package::Column::Namespace.is_null()
            })
            .filter(entity::package::Column::Name.eq(purl.name.clone()))
            .one(&self.connection(tx))
            .await?
            .map(|package| (self, package).into()))
    }

    pub(crate) async fn get_package_by_id(
        &self,
        id: i32,
        tx: Transactional<'_>,
    ) -> Result<Option<PackageContext>, Error> {
        if let Some(found) = entity::package::Entity::find_by_id(id)
            .one(&self.connection(tx))
            .await?
        {
            Ok(Some((self, found).into()))
        } else {
            Ok(None)
        }
    }
}

/// Live context for base package.
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
    /// Ensure the system knows about and contains a record for a *version range* of this package.
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

    /// Retrieve a *version range* package entry for this package, if it exists.
    ///
    /// Non-mutating to the system.
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

    /// Ensure the system knows about and contains a record for a *version* of this package.
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
            Err(Error::Purl(PurlErr::MissingVersion(purl.to_string())))
        }
    }

    /// Retrieve a *version* package entry for this package, if it exists.
    ///
    /// Non-mutating to the system.
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

    /// Retrieve known versions of this package.
    ///
    /// Non-mutating to the system.
    pub async fn get_versions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<Vec<PackageVersionContext>, Error> {
        Ok(entity::package_version::Entity::find()
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .all(&self.system.connection(tx))
            .await?
            .drain(0..)
            .map(|each| (self, each).into())
            .collect())
    }

    pub async fn get_versions_paginated(
        &self,
        paginated: Paginated,
        tx: Transactional<'_>,
    ) -> Result<PaginatedResults<PackageVersionContext>, Error> {
        let connection = self.system.connection(tx);

        let pagination = entity::package_version::Entity::find()
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .paginate(&connection, paginated.page_size);

        let num_items = pagination.num_items().await?;
        let num_pages = pagination.num_pages().await?;

        Ok(PaginatedResults {
            results: pagination
                .fetch_page(paginated.page)
                .await?
                .drain(0..)
                .map(|each| (self, each).into())
                .collect(),
            page: paginated.page_size,
            num_items,
            num_pages,
            prev_page: if paginated.page > 0 {
                Some(Paginated {
                    page_size: paginated.page_size,
                    page: paginated.page - 1,
                })
            } else {
                None
            },
            next_page: if paginated.page + 1 < num_pages {
                Some(Paginated {
                    page_size: paginated.page_size,
                    page: paginated.page + 1,
                })
            } else {
                None
            },
        })
    }

    /// Retrieve the aggregate vulnerability assertions for this base package.
    ///
    /// Assertions are a mixture of "affected" and "not affected", for any version
    /// of this package, from any relevant advisory making statements.
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

    /// Retrieve the aggregate "affected" vulnerability assertions for this base package.
    ///
    /// Assertions are "affected" for any version of this package,
    /// from any relevant advisory making statements.
    pub async fn affected_assertions(
        &self,
        tx: Transactional<'_>,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        #[derive(FromQueryResult, Debug)]
        struct AffectedVersion {
            start: String,
            end: String,
            advisory_id: i32,
            identifier: String,
            location: String,
            sha256: String,
        }

        let mut affected_version_ranges = entity::affected_package_version_range::Entity::find()
            .column_as(entity::package_version_range::Column::Start, "start")
            .column_as(entity::package_version_range::Column::End, "end")
            .column_as(entity::advisory::Column::Id, "advisory_id")
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

        let mut assertions = PackageVulnerabilityAssertions::default();
        for each in affected_version_ranges {
            let vulnerability = "not-implemented".to_string();

            assertions.assertions.push(Assertion::Affected {
                vulnerability,
                claimant: Claimant {
                    identifier: each.identifier,
                    location: each.location,
                    sha256: each.sha256,
                },
                start_version: each.start,
                end_version: each.end,
            });
        }

        Ok(assertions)
    }

    /// Retrieve the aggregate "not affected" vulnerability assertions for this base package.
    ///
    /// Assertions are "not affected" for any version of this package,
    /// from any relevant advisory making statements.
    pub async fn not_affected_assertions(
        &self,
        tx: Transactional<'_>,
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
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .into_model::<NotAffectedVersion>()
            .all(&self.system.connection(tx))
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
            })
        }

        Ok(assertions)
    }

    /// Retrieve all advisories mentioning this base package.
    pub async fn advisories_mentioning(
        &self,
        tx: Transactional<'_>,
    ) -> Result<Vec<AdvisoryContext>, Error> {
        let mut not_affected_subquery = entity::not_affected_package_version::Entity::find()
            .select_only()
            .column(entity::not_affected_package_version::Column::AdvisoryId)
            .join(
                JoinType::Join,
                entity::not_affected_package_version::Relation::PackageVersion.def(),
            )
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .into_query();

        let mut affected_subquery = entity::affected_package_version_range::Entity::find()
            .select_only()
            .column(entity::affected_package_version_range::Column::AdvisoryId)
            .join(
                JoinType::Join,
                entity::affected_package_version_range::Relation::PackageVersionRange.def(),
            )
            .filter(entity::package_version_range::Column::PackageId.eq(self.package.id))
            .into_query();

        let mut advisories = entity::advisory::Entity::find()
            .filter(
                entity::advisory::Column::Id.in_subquery(
                    not_affected_subquery
                        .union(UnionType::Distinct, affected_subquery)
                        .to_owned(),
                ),
            )
            .all(&self.system.connection(tx))
            .await?;

        Ok(advisories
            .drain(0..)
            .map(|advisory| (&self.system, advisory).into())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::db::{Paginated, Transactional};
    use crate::system::error::Error;
    use crate::system::InnerSystem;
    use trustify_common::purl::Purl;
    use sea_orm::{TransactionError, TransactionTrait};

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
    async fn get_versions_paginated() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("get_versions_paginated").await?;

        for v in 0..200 {
            let version = format!("pkg://maven/io.quarkus/quarkus-core@{v}");

            let _ = system
                .ingest_package_version(&version, Transactional::None)
                .await?;
        }

        let pkg = system
            .get_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
            .await?
            .unwrap();

        let all_versions = pkg.get_versions(Transactional::None).await?;

        assert_eq!(200, all_versions.len());

        let paginated = pkg
            .get_versions_paginated(
                Paginated {
                    page_size: 50,
                    page: 0,
                },
                Transactional::None,
            )
            .await?;

        assert!(paginated.prev_page.is_none());
        assert_eq!(
            paginated.next_page,
            Some(Paginated {
                page_size: 50,
                page: 1,
            })
        );
        assert_eq!(50, paginated.results.len());

        let next_paginated = pkg
            .get_versions_paginated(paginated.next_page.unwrap(), Transactional::None)
            .await?;

        assert_eq!(
            next_paginated.prev_page,
            Some(Paginated {
                page_size: 50,
                page: 0,
            })
        );

        assert!(next_paginated.next_page.is_some());
        assert_eq!(50, paginated.results.len());

        Ok(())
    }

    #[tokio::test]
    async fn ingest_qualified_packages_transactionally() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */

        let system = InnerSystem::for_test("ingest_qualified_packages_transactionally").await?;

        let db = system.db.clone();

        db.transaction(|tx| {
            Box::pin(async move {
                let pkg1 = system
                    .ingest_qualified_package(
                        "pkg://oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
                        Transactional::None,
                    )
                    .await?;

                let pkg2 = system
                    .ingest_qualified_package(
                        "pkg://oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
                        Transactional::None,
                    )
                    .await?;

                assert_eq!(pkg1, pkg2);

                Ok::<(), Error>(())
            })
        }).await?;

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

            let redhat_advisory_vulnerability = redhat_advisory
                .ingest_vulnerability("CVE-77", Transactional::None)
                .await?;

            redhat_advisory_vulnerability
                .ingest_affected_package_range(
                    "pkg://maven/io.quarkus/quarkus-core",
                    "1.0.2",
                    "1.2.0",
                    Transactional::None,
                )
                .await?;

            redhat_advisory_vulnerability
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

            let ghsa_advisory_vulnerability = ghsa_advisory
                .ingest_vulnerability("CVE-77", Transactional::None)
                .await?;

            ghsa_advisory_vulnerability
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

    let redhat_advisory_vulnerability = redhat_advisory
        .ingest_vulnerability("CVE-77", Transactional::None)
        .await?;

    redhat_advisory_vulnerability
        .ingest_not_affected_package_version(
            "pkg://maven/io.quarkus/quarkus-core@1.2",
            Transactional::None,
        )
        .await?;

    let ghsa_advisory = system
        .ingest_advisory("GHSA-1", "http://ghsa.com/ghsa-1", "2", Transactional::None)
        .await?;

    let ghsa_advisory_vulnerability = ghsa_advisory
        .ingest_vulnerability("CVE-77", Transactional::None)
        .await?;

    ghsa_advisory_vulnerability
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

    let redhat_advisory_vulnerability = redhat_advisory
        .ingest_vulnerability("CVE-87", Transactional::None)
        .await?;

    redhat_advisory_vulnerability
        .ingest_affected_package_range(
            "pkg://maven/io.quarkus/quarkus-core",
            "1.1",
            "1.3",
            Transactional::None,
        )
        .await?;

    redhat_advisory_vulnerability
        .ingest_not_affected_package_version(
            "pkg://maven/io.quarkus/quarkus-core@1.2",
            Transactional::None,
        )
        .await?;

    let ghsa_advisory = system
        .ingest_advisory("GHSA-1", "http://ghsa.com/ghsa-1", "2", Transactional::None)
        .await?;

    let ghsa_advisory_vulnerability = ghsa_advisory
        .ingest_vulnerability("CVE-87", Transactional::None)
        .await?;

    ghsa_advisory_vulnerability
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

#[tokio::test]
async fn advisories_mentioning_package() -> Result<(), anyhow::Error> {
    let system = InnerSystem::for_test("advisories_mentioning_package").await?;

    let redhat_advisory = system
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/rhsa-1",
            "2",
            Transactional::None,
        )
        .await?;

    let redhat_advisory_vulnerability = redhat_advisory
        .ingest_vulnerability("CVE-99", Transactional::None)
        .await?;

    redhat_advisory_vulnerability
        .ingest_affected_package_range(
            "pkg://maven/io.quarkus/quarkus-core",
            "1.1",
            "1.3",
            Transactional::None,
        )
        .await?;

    let ghsa_advisory = system
        .ingest_advisory("GHSA-1", "http://ghsa.gov/GHSA-1", "3", Transactional::None)
        .await?;

    let ghsa_advisory_vulnerability = ghsa_advisory
        .ingest_vulnerability("CVE-99", Transactional::None)
        .await?;

    ghsa_advisory_vulnerability
        .ingest_not_affected_package_version(
            "pkg://maven/io.quarkus/quarkus-core@1.2",
            Transactional::None,
        )
        .await?;

    let unrelated_advisory = system
        .ingest_advisory(
            "RHSA-299",
            "http://redhat.com/rhsa-299",
            "17",
            Transactional::None,
        )
        .await?;

    let unrelated_advisory_vulnerability = redhat_advisory
        .ingest_vulnerability("CVE-99", Transactional::None)
        .await?;

    unrelated_advisory_vulnerability
        .ingest_not_affected_package_version(
            "pkg://maven/io.quarkus/some-other-package@1.2",
            Transactional::None,
        )
        .await?;

    let pkg = system
        .get_package("pkg://maven/io.quarkus/quarkus-core", Transactional::None)
        .await?
        .unwrap();

    let advisories = pkg.advisories_mentioning(Transactional::None).await?;

    assert_eq!(2, advisories.len());
    assert!(advisories.contains(&redhat_advisory));
    assert!(advisories.contains(&ghsa_advisory));

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
