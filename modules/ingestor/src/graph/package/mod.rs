//! Support for packages.

use std::fmt::{Debug, Formatter};

use sea_orm::RelationTrait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    QueryTrait, Set,
};
use sea_query::{JoinType, SelectStatement, UnionType};

use package_version::PackageVersionContext;
use package_version_range::PackageVersionRangeContext;
use qualified_package::QualifiedPackageContext;
use trustify_common::{
    db::{limiter::LimiterTrait, Transactional},
    model::{Paginated, PaginatedResults},
    package::{Assertion, Claimant, PackageVulnerabilityAssertions},
    purl::{Purl, PurlErr},
};
use trustify_entity as entity;
use trustify_entity::package;

use crate::graph::advisory::AdvisoryContext;
use crate::graph::error::Error;
use crate::graph::Graph;

pub mod package_version;
pub mod package_version_range;
pub mod qualified_package;

impl Graph {
    /// Ensure the fetch knows about and contains a record for a *fully-qualified* package.
    ///
    /// This method will ensure the versioned package being referenced is also ingested.
    ///
    /// The `pkg` parameter does not necessarily require the presence of qualifiers, but
    /// is assumed to be *complete*.
    pub async fn ingest_qualified_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<QualifiedPackageContext, Error> {
        if let Some(found) = self.get_qualified_package(purl.clone(), &tx).await? {
            return Ok(found);
        }

        let package_version = self.ingest_package_version(purl.clone(), &tx).await?;

        package_version.ingest_qualified_package(purl, &tx).await
    }

    /// Ensure the fetch knows about and contains a record for a *versioned* package.
    ///
    /// This method will ensure the package being referenced is also ingested.
    pub async fn ingest_package_version<TX: AsRef<Transactional>>(
        &self,
        pkg: Purl,
        tx: TX,
    ) -> Result<PackageVersionContext, Error> {
        if let Some(found) = self.get_package_version(pkg.clone(), &tx).await? {
            return Ok(found);
        }
        let package = self.ingest_package(pkg.clone(), &tx).await?;

        package.ingest_package_version(pkg.clone(), &tx).await
    }

    /// Ensure the fetch knows about and contains a record for a *versioned range* of a package.
    ///
    /// This method will ensure the package being referenced is also ingested.
    pub async fn ingest_package_version_range<TX: AsRef<Transactional>>(
        &self,
        pkg: Purl,
        start: &str,
        end: &str,
        tx: TX,
    ) -> Result<PackageVersionRangeContext, Error> {
        let package = self.ingest_package(pkg.clone(), &tx).await?;

        package
            .ingest_package_version_range(pkg.clone(), start, end, &tx)
            .await
    }

    /// Ensure the fetch knows about and contains a record for a *versionless* package.
    ///
    /// This method will ensure the package being referenced is also ingested.
    pub async fn ingest_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<PackageContext, Error> {
        if let Some(found) = self.get_package(purl.clone(), &tx).await? {
            Ok(found)
        } else {
            let model = entity::package::ActiveModel {
                id: Default::default(),
                r#type: Set(purl.ty.clone()),
                namespace: Set(purl.namespace.clone()),
                name: Set(purl.name.clone()),
            };

            Ok(PackageContext::new(
                self,
                model.insert(&self.connection(&tx)).await?,
            ))
        }
    }

    /// Retrieve a *fully-qualified* package entry, if it exists.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_qualified_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        if let Some(package_version) = self.get_package_version(purl.clone(), &tx).await? {
            package_version.get_qualified_package(purl, &tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_qualified_package_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<QualifiedPackageContext>, Error> {
        let found = entity::qualified_package::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?;

        if let Some(qualified_package) = found {
            if let Some(package_version) = self
                .get_package_version_by_id(qualified_package.package_version_id, tx)
                .await?
            {
                Ok(Some(QualifiedPackageContext::new(
                    &package_version,
                    qualified_package.clone(),
                )))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub async fn get_qualified_packages_by_query<TX: AsRef<Transactional>>(
        &self,
        query: SelectStatement,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let found = entity::qualified_package::Entity::find()
            .filter(entity::qualified_package::Column::Id.in_subquery(query))
            .all(&self.connection(&tx))
            .await?;

        let mut package_versions = Vec::new();

        for base in &found {
            if let Some(package_version) = self
                .get_package_version_by_id(base.package_version_id, &tx)
                .await?
            {
                let qualified_package =
                    QualifiedPackageContext::new(&package_version, base.clone());
                package_versions.push(qualified_package);
            }
        }

        Ok(package_versions)
    }

    /// Retrieve a *versioned* package entry, if it exists.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_package_version<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Option<PackageVersionContext<'_>>, Error> {
        if let Some(pkg) = self.get_package(purl.clone(), &tx).await? {
            pkg.get_package_version(purl, &tx).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_package_version_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<PackageVersionContext>, Error> {
        if let Some(package_version) = entity::package_version::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
        {
            if let Some(package) = self
                .get_package_by_id(package_version.package_id, &tx)
                .await?
            {
                Ok(Some(PackageVersionContext::new(&package, package_version)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Retrieve a *version range* of a package entry, if it exists.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_package_version_range<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        start: &str,
        end: &str,
        tx: TX,
    ) -> Result<Option<PackageVersionRangeContext>, Error> {
        if let Some(pkg) = self.get_package(purl.clone(), &tx).await? {
            pkg.get_package_version_range(purl, start, end, &tx).await
        } else {
            Ok(None)
        }
    }

    /// Retrieve a *versionless* package entry, if it exists.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Option<PackageContext>, Error> {
        Ok(entity::package::Entity::find()
            .filter(entity::package::Column::Type.eq(purl.ty))
            .filter(if let Some(ns) = purl.namespace {
                entity::package::Column::Namespace.eq(ns)
            } else {
                entity::package::Column::Namespace.is_null()
            })
            .filter(entity::package::Column::Name.eq(purl.name))
            .one(&self.connection(&tx))
            .await?
            .map(|package| PackageContext::new(self, package)))
    }

    pub async fn get_package_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<PackageContext>, Error> {
        if let Some(found) = entity::package::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
        {
            Ok(Some(PackageContext::new(self, found)))
        } else {
            Ok(None)
        }
    }
}

/// Live context for base package.
#[derive(Clone)]
pub struct PackageContext<'g> {
    pub graph: &'g Graph,
    pub package: entity::package::Model,
}

impl Debug for PackageContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package.fmt(f)
    }
}

impl<'g> PackageContext<'g> {
    pub fn new(graph: &'g Graph, package: package::Model) -> Self {
        Self { graph, package }
    }

    /// Ensure the fetch knows about and contains a record for a *version range* of this package.
    pub async fn ingest_package_version_range<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        start: &str,
        end: &str,
        tx: TX,
    ) -> Result<PackageVersionRangeContext<'g>, Error> {
        if let Some(found) = self
            .get_package_version_range(purl, start, end, &tx)
            .await?
        {
            Ok(found)
        } else {
            let entity = entity::package_version_range::ActiveModel {
                id: Default::default(),
                package_id: Set(self.package.id),
                start: Set(start.to_string()),
                end: Set(end.to_string()),
            };

            Ok(PackageVersionRangeContext::new(
                self,
                entity.insert(&self.graph.connection(&tx)).await?,
            ))
        }
    }

    /// Retrieve a *version range* package entry for this package, if it exists.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_package_version_range<TX: AsRef<Transactional>>(
        &self,
        _purl: Purl,
        start: &str,
        end: &str,
        tx: TX,
    ) -> Result<Option<PackageVersionRangeContext<'g>>, Error> {
        Ok(entity::package_version_range::Entity::find()
            .filter(entity::package_version_range::Column::PackageId.eq(self.package.id))
            .filter(entity::package_version_range::Column::Start.eq(start.to_string()))
            .filter(entity::package_version_range::Column::End.eq(end.to_string()))
            .one(&self.graph.connection(&tx))
            .await?
            .map(|package_version_range| {
                PackageVersionRangeContext::new(self, package_version_range)
            }))
    }

    /// Ensure the fetch knows about and contains a record for a *version* of this package.
    pub async fn ingest_package_version<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<PackageVersionContext<'g>, Error> {
        if let Some(version) = &purl.version {
            if let Some(found) = self.get_package_version(purl.clone(), &tx).await? {
                Ok(found)
            } else {
                let model = entity::package_version::ActiveModel {
                    id: Default::default(),
                    package_id: Set(self.package.id),
                    version: Set(version.clone()),
                };

                Ok(PackageVersionContext::new(
                    self,
                    model.insert(&self.graph.connection(&tx)).await?,
                ))
            }
        } else {
            Err(Error::Purl(PurlErr::MissingVersion(purl.to_string())))
        }
    }

    /// Retrieve a *version* package entry for this package, if it exists.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_package_version<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Option<PackageVersionContext<'g>>, Error> {
        if let Some(package_version) = entity::package_version::Entity::find()
            .join(
                JoinType::Join,
                entity::package_version::Relation::Package.def(),
            )
            .filter(entity::package::Column::Id.eq(self.package.id))
            .filter(entity::package_version::Column::Version.eq(purl.version.clone()))
            .one(&self.graph.connection(&tx))
            .await?
        {
            Ok(Some(PackageVersionContext::new(self, package_version)))
        } else {
            Ok(None)
        }
    }

    /// Retrieve known versions of this package.
    ///
    /// Non-mutating to the fetch.
    pub async fn get_versions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<PackageVersionContext>, Error> {
        Ok(entity::package_version::Entity::find()
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .all(&self.graph.connection(&tx))
            .await?
            .drain(0..)
            .map(|each| PackageVersionContext::new(self, each))
            .collect())
    }

    pub async fn get_versions_paginated<TX: AsRef<Transactional>>(
        &self,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<PackageVersionContext>, Error> {
        let connection = self.graph.connection(&tx);

        let limiter = entity::package_version::Entity::find()
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .limiting(&connection, paginated.limit, paginated.offset);

        Ok(PaginatedResults {
            total: limiter.total().await?,
            items: limiter
                .fetch()
                .await?
                .drain(0..)
                .map(|each| PackageVersionContext::new(self, each))
                .collect(),
        })
    }

    /// Retrieve the aggregate vulnerability assertions for this base package.
    ///
    /// Assertions are a mixture of "affected" and "not affected", for any version
    /// of this package, from any relevant advisory making statements.
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

    /// Retrieve the aggregate "affected" vulnerability assertions for this base package.
    ///
    /// Assertions are "affected" for any version of this package,
    /// from any relevant advisory making statements.
    pub async fn affected_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        #[derive(FromQueryResult, Debug)]
        struct AffectedVersion {
            start: String,
            end: String,
            identifier: String,
            location: String,
            sha256: String,
        }

        let affected_version_ranges = entity::affected_package_version_range::Entity::find()
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
            .all(&self.graph.connection(&tx))
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
    pub async fn not_affected_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<PackageVulnerabilityAssertions, Error> {
        #[derive(FromQueryResult, Debug)]
        struct NotAffectedVersion {
            version: String,
            identifier: String,
            location: String,
            sha256: String,
        }

        let not_affected_versions = entity::not_affected_package_version::Entity::find()
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
            .all(&self.graph.connection(&tx))
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
    pub async fn advisories_mentioning<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<AdvisoryContext<'g>>, Error> {
        let mut not_affected_subquery = entity::not_affected_package_version::Entity::find()
            .select_only()
            .column(entity::not_affected_package_version::Column::AdvisoryId)
            .join(
                JoinType::Join,
                entity::not_affected_package_version::Relation::PackageVersion.def(),
            )
            .filter(entity::package_version::Column::PackageId.eq(self.package.id))
            .into_query();

        let affected_subquery = entity::affected_package_version_range::Entity::find()
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
            .all(&self.graph.connection(&tx))
            .await?;

        Ok(advisories
            .drain(0..)
            .map(|advisory| AdvisoryContext::new(self.graph, advisory))
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU64;

    use sea_orm::{
        EntityTrait, IntoSimpleExpr, QueryFilter, QuerySelect, QueryTrait, TransactionTrait,
    };
    use sea_query::{Expr, SimpleExpr};
    use serde_json::json;
    use test_log::test;

    use trustify_common::db::{Database, Transactional};
    use trustify_common::model::Paginated;
    use trustify_common::purl::Purl;
    use trustify_entity::qualified_package;
    use trustify_entity::qualified_package::Qualifiers;

    use crate::graph::error::Error;
    use crate::graph::Graph;

    #[test(tokio::test)]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_packages").await?;
        let system = Graph::new(db);

        let pkg1 = system
            .ingest_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_package(
                "pkg://maven/io.quarkus/quarkus-addons".try_into()?,
                Transactional::None,
            )
            .await?;

        assert_eq!(pkg1.package.id, pkg2.package.id,);

        assert_ne!(pkg1.package.id, pkg3.package.id);

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_package_versions_missing_version() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_package_versions_missing_version").await?;
        let system = Graph::new(db);

        let result = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-addons".try_into()?,
                Transactional::None,
            )
            .await;

        assert!(result.is_err());

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_package_versions() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_package_versions").await?;
        let system = Graph::new(db);

        let pkg1 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_package_version(
                "pkg://maven/io.quarkus/quarkus-core@4.5.6".try_into()?,
                Transactional::None,
            )
            .await?;

        assert_eq!(pkg1.package.package.id, pkg2.package.package.id);
        assert_eq!(pkg1.package_version.id, pkg2.package_version.id);

        assert_eq!(pkg1.package.package.id, pkg3.package.package.id);
        assert_ne!(pkg1.package_version.id, pkg3.package_version.id);

        Ok(())
    }

    #[test(tokio::test)]
    async fn get_versions_paginated() -> Result<(), anyhow::Error> {
        let db = Database::for_test("get_versions_paginated").await?;
        let system = Graph::new(db);

        const TOTAL_ITEMS: u64 = 200;
        let _page_size = NonZeroU64::new(50).unwrap();

        for v in 0..TOTAL_ITEMS {
            let version = format!("pkg://maven/io.quarkus/quarkus-core@{v}").try_into()?;

            let _ = system
                .ingest_package_version(version, Transactional::None)
                .await?;
        }

        let pkg = system
            .get_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
            .await?
            .unwrap();

        let all_versions = pkg.get_versions(Transactional::None).await?;

        assert_eq!(TOTAL_ITEMS, all_versions.len() as u64);

        let paginated = pkg
            .get_versions_paginated(
                Paginated {
                    offset: 50,
                    limit: 50,
                },
                Transactional::None,
            )
            .await?;

        assert_eq!(TOTAL_ITEMS, paginated.total);
        assert_eq!(50, paginated.items.len());

        let _next_paginated = pkg
            .get_versions_paginated(
                Paginated {
                    offset: 100,
                    limit: 50,
                },
                Transactional::None,
            )
            .await?;

        assert_eq!(TOTAL_ITEMS, paginated.total);
        assert_eq!(50, paginated.items.len());

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_qualified_packages_transactionally() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_qualified_packages_transactionally").await?;
        let system = Graph::new(db.clone());

        let tx_system = system.clone();

        db.transaction(|_tx| {
            Box::pin(async move {
                let pkg1 = tx_system
                    .ingest_qualified_package(
                        "pkg://oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012".try_into()?,
                        Transactional::None,
                    )
                    .await?;

                let pkg2 = tx_system
                    .ingest_qualified_package(
                        "pkg://oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012".try_into()?,
                        Transactional::None,
                    )
                    .await?;

                assert_eq!(pkg1, pkg2);

                Ok::<(), Error>(())
            })
        }).await?;

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_qualified_packages() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_qualified_packages").await?;
        let system = Graph::new(db);

        let pkg1 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg2 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg3 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg4 = system
            .ingest_qualified_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar".try_into()?,
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

    #[test(tokio::test)]
    async fn query_qualified_packages() -> Result<(), anyhow::Error> {
        let db = Database::for_test("query_qualified_packages").await?;
        let graph = Graph::new(db);

        for i in [
            "pkg://maven/io.quarkus/quarkus-core@1.2.3",
            "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=jar",
            "pkg://maven/io.quarkus/quarkus-core@1.2.3?type=pom",
        ] {
            graph
                .ingest_qualified_package(i.try_into()?, Transactional::None)
                .await?;
        }

        let qualifiers = json!({"type": "jar"});
        // qualifiers @> '{"type": "jar"}'::jsonb
        let select = qualified_package::Entity::find()
            .select_only()
            .column(qualified_package::Column::Id)
            .filter(Expr::cust_with_exprs(
                "$1 @> $2::jsonb",
                [
                    qualified_package::Column::Qualifiers.into_simple_expr(),
                    SimpleExpr::Value(qualifiers.into()),
                ],
            ))
            .into_query();
        let result = graph
            .get_qualified_packages_by_query(select, Transactional::None)
            .await?;

        log::info!("{result:?}");

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].qualified_package.qualifiers,
            Some(Qualifiers(HashMap::from_iter([(
                "type".into(),
                "jar".into()
            )])))
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_package_version_ranges() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_package_version_ranges").await?;
        let system = Graph::new(db);

        let range1 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let range2 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.0",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let range3 = system
            .ingest_package_version_range(
                "pkg://maven/io.quarkus/quarkus-addons".try_into()?,
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

    #[test(tokio::test)]
    async fn package_affected_assertions() -> Result<(), anyhow::Error> {
        let db = Database::for_test("package_affected_assertions").await?;
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
            .link_to_vulnerability("CVE-77", Transactional::None)
            .await?;

        redhat_advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        redhat_advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-addons".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let ghsa_advisory = system
            .ingest_advisory(
                "GHSA-1",
                "http://ghsa.com/ghsa-1",
                "3",
                (),
                Transactional::None,
            )
            .await?;

        let ghsa_advisory_vulnerability = ghsa_advisory
            .link_to_vulnerability("CVE-77", Transactional::None)
            .await?;

        ghsa_advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.0.2",
                "1.2.0",
                Transactional::None,
            )
            .await?;

        let pkg_core = system
            .get_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
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
            .get_package(
                "pkg://maven/io.quarkus/quarkus-addons".try_into()?,
                Transactional::None,
            )
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

    #[test(tokio::test)]
    async fn package_not_affected_assertions() -> Result<(), anyhow::Error> {
        let db = Database::for_test("package_not_affected_assertions").await?;
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
            .link_to_vulnerability("CVE-77", Transactional::None)
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
            .link_to_vulnerability("CVE-77", Transactional::None)
            .await?;

        ghsa_advisory_vulnerability
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.2".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg = system
            .get_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
            .await?
            .unwrap();

        let assertions = pkg.not_affected_assertions(Transactional::None).await?;

        assert_eq!(assertions.assertions.len(), 2);

        Ok(())
    }

    #[test(tokio::test)]
    async fn package_vulnerability_assertions() -> Result<(), anyhow::Error> {
        let db = Database::for_test("package_vulnerability_assertions").await?;
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
            .link_to_vulnerability("CVE-87", Transactional::None)
            .await?;

        redhat_advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.1",
                "1.3",
                Transactional::None,
            )
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
            .link_to_vulnerability("CVE-87", Transactional::None)
            .await?;

        ghsa_advisory_vulnerability
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2.2".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg = system
            .get_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
            .await?
            .unwrap();

        let assertions = pkg.vulnerability_assertions(Transactional::None).await?;

        assert_eq!(assertions.assertions.len(), 3);

        Ok(())
    }

    #[test(tokio::test)]
    async fn advisories_mentioning_package() -> Result<(), anyhow::Error> {
        let db = Database::for_test("advisories_mentioning_package").await?;
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
            .link_to_vulnerability("CVE-99", Transactional::None)
            .await?;

        redhat_advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                "1.1",
                "1.3",
                Transactional::None,
            )
            .await?;

        let ghsa_advisory = system
            .ingest_advisory(
                "GHSA-1",
                "http://ghsa.gov/GHSA-1",
                "3",
                (),
                Transactional::None,
            )
            .await?;

        let ghsa_advisory_vulnerability = ghsa_advisory
            .link_to_vulnerability("CVE-99", Transactional::None)
            .await?;

        ghsa_advisory_vulnerability
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/quarkus-core@1.2".try_into()?,
                Transactional::None,
            )
            .await?;

        let _unrelated_advisory = system
            .ingest_advisory(
                "RHSA-299",
                "http://redhat.com/rhsa-299",
                "17",
                (),
                Transactional::None,
            )
            .await?;

        let unrelated_advisory_vulnerability = redhat_advisory
            .link_to_vulnerability("CVE-99", Transactional::None)
            .await?;

        unrelated_advisory_vulnerability
            .ingest_not_affected_package_version(
                "pkg://maven/io.quarkus/some-other-package@1.2".try_into()?,
                Transactional::None,
            )
            .await?;

        let pkg = system
            .get_package(
                "pkg://maven/io.quarkus/quarkus-core".try_into()?,
                Transactional::None,
            )
            .await?
            .unwrap();

        let advisories = pkg.advisories_mentioning(Transactional::None).await?;

        assert_eq!(2, advisories.len());
        assert!(advisories.contains(&redhat_advisory));
        assert!(advisories.contains(&ghsa_advisory));

        Ok(())
    }
}
