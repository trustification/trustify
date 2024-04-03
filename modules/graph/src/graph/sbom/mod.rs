//! Support for SBOMs.

use super::error::Error;
use crate::db::{LeftPackageId, QualifiedPackageTransitive};
use crate::graph::advisory::AdvisoryContext;
use crate::graph::cpe::CpeContext;
use crate::graph::package::qualified_package::QualifiedPackageContext;
use crate::graph::Graph;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    QueryTrait, RelationTrait, Select, Set,
};
use sea_query::{Condition, Func, JoinType, Query, SimpleExpr};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use trustify_common::cpe::Cpe;
use trustify_common::db::Transactional;
use trustify_common::package::PackageVulnerabilityAssertions;
use trustify_common::purl::Purl;
use trustify_common::sbom::SbomLocator;
use trustify_entity as entity;
use trustify_entity::relationship::Relationship;

pub mod spdx;

type SelectEntity<E> = Select<E>;

impl Graph {
    pub async fn get_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(entity::sbom::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    pub async fn get_sbom(
        &self,
        location: &str,
        sha256: &str,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(entity::sbom::Entity::find()
            .filter(Condition::all().add(entity::sbom::Column::Location.eq(location)))
            .filter(Condition::all().add(entity::sbom::Column::Sha256.eq(sha256.to_string())))
            .one(&self.db)
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    pub async fn ingest_sbom<TX: AsRef<Transactional>>(
        &self,
        location: &str,
        sha256: &str,
        tx: TX,
    ) -> Result<SbomContext, Error> {
        if let Some(found) = self.get_sbom(location, sha256).await? {
            return Ok(found);
        }

        let model = entity::sbom::ActiveModel {
            location: Set(location.to_string()),
            sha256: Set(sha256.to_string()),
            ..Default::default()
        };

        Ok((self, model.insert(&self.db).await?).into())
    }

    /// Fetch a single SBOM located via internal `id`, external `location` (URL),
    /// described pURL, described CPE, or sha256 hash.
    ///
    /// Fetching by pURL, CPE or location may result in a single result where multiple
    /// may exist in the graph in actuality.
    ///
    /// If the requested SBOM does not exist in the graph, it will not exist
    /// after this query either. This function is *non-mutating*.
    pub async fn locate_sbom<TX: AsRef<Transactional>>(
        &self,
        sbom_locator: SbomLocator,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => self.locate_sbom_by_id(id, tx).await,
            SbomLocator::Location(location) => self.locate_sbom_by_location(&location, tx).await,
            SbomLocator::Sha256(sha256) => self.locate_sbom_by_sha256(&sha256, tx).await,
            SbomLocator::Purl(purl) => self.locate_sbom_by_purl(purl, tx).await,
            SbomLocator::Cpe(cpe) => self.locate_sbom_by_cpe22(&cpe, tx).await,
        }
    }

    pub async fn locate_sboms<TX: AsRef<Transactional>>(
        &self,
        sbom_locator: SbomLocator,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => {
                if let Some(sbom) = self.locate_sbom_by_id(id, tx).await? {
                    Ok(vec![sbom])
                } else {
                    Ok(vec![])
                }
            }
            SbomLocator::Location(location) => self.locate_sboms_by_location(&location, tx).await,
            SbomLocator::Sha256(sha256) => self.locate_sboms_by_sha256(&sha256, tx).await,
            SbomLocator::Purl(purl) => self.locate_sboms_by_purl(purl, tx).await,
            SbomLocator::Cpe(cpe) => self.locate_sboms_by_cpe22(cpe, tx).await,
            _ => todo!(),
        }
    }

    async fn locate_one_sbom<TX: AsRef<Transactional>>(
        &self,
        query: SelectEntity<entity::sbom::Entity>,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(query
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    async fn locate_many_sboms<TX: AsRef<Transactional>>(
        &self,
        query: SelectEntity<entity::sbom::Entity>,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        Ok(query
            .all(&self.connection(&tx))
            .await?
            .drain(0..)
            .map(|sbom| (self, sbom).into())
            .collect())
    }

    async fn locate_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let query = entity::sbom::Entity::find_by_id(id);
        Ok(entity::sbom::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    async fn locate_sbom_by_location<TX: AsRef<Transactional>>(
        &self,
        location: &str,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            entity::sbom::Entity::find()
                .filter(entity::sbom::Column::Location.eq(location.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sboms_by_location<TX: AsRef<Transactional>>(
        &self,
        location: &str,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            entity::sbom::Entity::find()
                .filter(entity::sbom::Column::Location.eq(location.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sbom_by_sha256<TX: AsRef<Transactional>>(
        &self,
        sha256: &str,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            entity::sbom::Entity::find()
                .filter(entity::sbom::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sboms_by_sha256<TX: AsRef<Transactional>>(
        &self,
        sha256: &str,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            entity::sbom::Entity::find()
                .filter(entity::sbom::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sbom_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, &tx).await?;

        if let Some(package) = package {
            self.locate_one_sbom(
                entity::sbom::Entity::find()
                    .join(
                        JoinType::LeftJoin,
                        entity::sbom_describes_package::Relation::Sbom.def().rev(),
                    )
                    .filter(
                        entity::sbom_describes_package::Column::QualifiedPackageId
                            .eq(package.qualified_package.id),
                    ),
                &tx,
            )
            .await
        } else {
            Ok(None)
        }
    }

    async fn locate_sboms_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, &tx).await?;

        if let Some(package) = package {
            self.locate_many_sboms(
                entity::sbom::Entity::find()
                    .join(
                        JoinType::LeftJoin,
                        entity::sbom_describes_package::Relation::Sbom.def().rev(),
                    )
                    .filter(
                        entity::sbom_describes_package::Column::QualifiedPackageId
                            .eq(package.qualified_package.id),
                    ),
                &tx,
            )
            .await
        } else {
            Ok(vec![])
        }
    }

    async fn locate_sbom_by_cpe22<TX: AsRef<Transactional>>(
        &self,
        cpe: &Cpe,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        if let Some(cpe) = self.get_cpe(cpe.clone(), &tx).await? {
            self.locate_one_sbom(
                entity::sbom::Entity::find()
                    .join(
                        JoinType::LeftJoin,
                        entity::sbom_describes_cpe::Relation::Sbom.def().rev(),
                    )
                    .filter(entity::sbom_describes_cpe::Column::CpeId.eq(cpe.cpe.id)),
                &tx,
            )
            .await
        } else {
            Ok(None)
        }
    }

    async fn locate_sboms_by_cpe22<C: Into<Cpe>, TX: AsRef<Transactional>>(
        &self,
        cpe: C,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        if let Some(found) = self.get_cpe(cpe, &tx).await? {
            self.locate_many_sboms(
                entity::sbom::Entity::find()
                    .join(
                        JoinType::LeftJoin,
                        entity::sbom_describes_cpe::Relation::Sbom.def().rev(),
                    )
                    .filter(entity::sbom_describes_cpe::Column::CpeId.eq(found.cpe.id)),
                &tx,
            )
            .await
        } else {
            Ok(vec![])
        }
    }
}

#[derive(Clone)]
pub struct SbomContext {
    pub(crate) graph: Graph,
    pub sbom: entity::sbom::Model,
}

impl PartialEq for SbomContext {
    fn eq(&self, other: &Self) -> bool {
        self.sbom.eq(&other.sbom)
    }
}

impl Debug for SbomContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.sbom.fmt(f)
    }
}

impl From<(&Graph, entity::sbom::Model)> for SbomContext {
    fn from((system, sbom): (&Graph, entity::sbom::Model)) -> Self {
        Self {
            graph: system.clone(),
            sbom,
        }
    }
}

impl SbomContext {
    pub async fn ingest_describes_cpe22<C: Into<Cpe>, TX: AsRef<Transactional>>(
        &self,
        cpe: C,
        tx: TX,
    ) -> Result<(), Error> {
        let cpe = self.graph.ingest_cpe22(cpe, &tx).await?;

        let fetch = entity::sbom_describes_cpe::Entity::find()
            .filter(entity::sbom_describes_cpe::Column::SbomId.eq(self.sbom.id))
            .filter(entity::sbom_describes_cpe::Column::CpeId.eq(cpe.cpe.id))
            .one(&self.graph.connection(&tx))
            .await?;

        if fetch.is_none() {
            let model = entity::sbom_describes_cpe::ActiveModel {
                sbom_id: Set(self.sbom.id),
                cpe_id: Set(cpe.cpe.id),
            };

            model.insert(&self.graph.connection(&tx)).await?;
        }
        Ok(())
    }

    pub async fn ingest_describes_package<TX: AsRef<Transactional>>(
        &self,
        purl: Purl,
        tx: TX,
    ) -> Result<(), Error> {
        let fetch = entity::sbom_describes_package::Entity::find()
            .filter(
                Condition::all()
                    .add(entity::sbom_describes_package::Column::SbomId.eq(self.sbom.id)),
            )
            .one(&self.graph.connection(&tx))
            .await?;

        if fetch.is_none() {
            let package = self.graph.ingest_qualified_package(purl, &tx).await?;

            let model = entity::sbom_describes_package::ActiveModel {
                sbom_id: Set(self.sbom.id),
                qualified_package_id: Set(package.qualified_package.id),
            };

            model.insert(&self.graph.connection(&tx)).await?;
        }
        Ok(())
    }

    pub async fn describes_packages<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        self.graph
            .get_qualified_packages_by_query(
                entity::sbom_describes_package::Entity::find()
                    .select_only()
                    .column(entity::sbom_describes_package::Column::QualifiedPackageId)
                    .filter(entity::sbom_describes_package::Column::SbomId.eq(self.sbom.id))
                    .into_query(),
                tx,
            )
            .await
    }

    pub async fn describes_cpe22s<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Vec<CpeContext>, Error> {
        self.graph
            .get_cpe_by_query(
                entity::sbom_describes_cpe::Entity::find()
                    .select_only()
                    .column(entity::sbom_describes_cpe::Column::CpeId)
                    .filter(entity::sbom_describes_cpe::Column::SbomId.eq(self.sbom.id))
                    .into_query(),
                tx,
            )
            .await
    }

    /// Within the context of *this* SBOM, ingest a relationship between
    /// two packages.
    async fn ingest_package_relates_to_package<TX: AsRef<Transactional>>(
        &self,
        left_package_input: Purl,
        relationship: Relationship,
        right_package_input: Purl,
        tx: TX,
    ) -> Result<(), Error> {
        let left_package = self
            .graph
            .ingest_qualified_package(left_package_input.clone(), &tx)
            .await;

        let right_package = self
            .graph
            .ingest_qualified_package(right_package_input.clone(), &tx)
            .await;

        match (&left_package, &right_package) {
            (Ok(left_package), Ok(right_package)) => {
                if entity::package_relates_to_package::Entity::find()
                    .filter(entity::package_relates_to_package::Column::SbomId.eq(self.sbom.id))
                    .filter(
                        entity::package_relates_to_package::Column::LeftPackageId
                            .eq(left_package.qualified_package.id),
                    )
                    .filter(
                        entity::package_relates_to_package::Column::Relationship.eq(relationship),
                    )
                    .filter(
                        entity::package_relates_to_package::Column::RightPackageId
                            .eq(right_package.qualified_package.id),
                    )
                    .one(&self.graph.connection(&tx))
                    .await?
                    .is_none()
                {
                    let entity = entity::package_relates_to_package::ActiveModel {
                        left_package_id: Set(left_package.qualified_package.id),
                        relationship: Set(relationship),
                        right_package_id: Set(right_package.qualified_package.id),
                        sbom_id: Set(self.sbom.id),
                    };

                    entity.insert(&self.graph.connection(&tx)).await?;
                }
            }
            (Err(_), Err(_)) => {
                log::warn!(
                    "unable to ingest relationships between non-fully-qualified packages {}, {}",
                    left_package_input.to_string(),
                    right_package_input.to_string()
                );
            }
            (Err(_), Ok(_)) => {
                log::warn!(
                    "unable to ingest relationships involving a non-fully-qualified package {}",
                    left_package_input.to_string()
                );
            }
            (Ok(_), Err(_)) => {
                log::warn!(
                    "unable to ingest relationships involving a non-fully-qualified package {}",
                    right_package_input.to_string()
                );
            }
        }

        Ok(())
    }

    pub async fn related_packages_transitively_x<TX: AsRef<Transactional>>(
        &self,
        relationship: Relationship,
        pkg: Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, &tx).await?;

        if let Some(pkg) = pkg {
            #[derive(Debug, FromQueryResult)]
            struct Related {
                left_package_id: i32,
                right_package_id: i32,
            }

            Ok(self
                .graph
                .get_qualified_packages_by_query(
                    Query::select()
                        .column(LeftPackageId)
                        .from_function(
                            Func::cust(QualifiedPackageTransitive).args([
                                self.sbom.id.into(),
                                pkg.qualified_package.id.into(),
                                relationship.into(),
                            ]),
                            QualifiedPackageTransitive,
                        )
                        .to_owned(),
                    &tx,
                )
                .await?)
        } else {
            Ok(vec![])
        }
    }

    pub async fn related_packages_transitively<TX: AsRef<Transactional>>(
        &self,
        relationships: &[Relationship],
        pkg: Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, &tx).await?;

        if let Some(pkg) = pkg {
            #[derive(Debug, FromQueryResult)]
            struct Related {
                left_package_id: i32,
                right_package_id: i32,
            }

            let rels: SimpleExpr = SimpleExpr::Custom(format!(
                "array[{}]",
                relationships
                    .iter()
                    .map(|e| (*e as i32).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));

            let sbom_id: SimpleExpr = self.sbom.id.into();
            let qualified_package_id: SimpleExpr = pkg.qualified_package.id.into();

            Ok(self
                .graph
                .get_qualified_packages_by_query(
                    Query::select()
                        .column(LeftPackageId)
                        .from_function(
                            Func::cust(QualifiedPackageTransitive).args([
                                sbom_id,
                                qualified_package_id,
                                rels,
                            ]),
                            QualifiedPackageTransitive,
                        )
                        .to_owned(),
                    &tx,
                )
                .await?)
        } else {
            Ok(vec![])
        }
    }

    pub async fn related_packages<TX: AsRef<Transactional>>(
        &self,
        relationship: Relationship,
        pkg: Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, &tx).await?;

        if let Some(pkg) = pkg {
            let related_query = entity::package_relates_to_package::Entity::find()
                .select_only()
                .column(entity::package_relates_to_package::Column::LeftPackageId)
                .filter(entity::package_relates_to_package::Column::SbomId.eq(self.sbom.id))
                .filter(entity::package_relates_to_package::Column::Relationship.eq(relationship))
                .filter(
                    entity::package_relates_to_package::Column::RightPackageId
                        .eq(pkg.qualified_package.id),
                )
                .into_query();

            let mut found = entity::qualified_package::Entity::find()
                .filter(entity::qualified_package::Column::Id.in_subquery(related_query))
                .find_with_related(entity::package_qualifier::Entity)
                .all(&self.graph.connection(&tx))
                .await?;

            let mut related = Vec::new();

            for (base, qualifiers) in found.drain(0..) {
                if let Some(package_version) =
                    entity::package_version::Entity::find_by_id(base.package_version_id)
                        .one(&self.graph.connection(&tx))
                        .await?
                {
                    if let Some(package) =
                        entity::package::Entity::find_by_id(package_version.package_id)
                            .one(&self.graph.connection(&tx))
                            .await?
                    {
                        let package = (&self.graph, package).into();
                        let package_version = (&package, package_version).into();

                        let qualifiers_map = qualifiers
                            .iter()
                            .map(|qualifier| (qualifier.key.clone(), qualifier.value.clone()))
                            .collect::<HashMap<_, _>>();

                        related.push((&package_version, base, qualifiers_map).into());
                    }
                }
            }

            Ok(related)
        } else {
            log::info!("no package");
            Ok(vec![])
        }
    }

    pub async fn vulnerability_assertions<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<HashMap<QualifiedPackageContext, PackageVulnerabilityAssertions>, Error> {
        let described_packages = self.describes_packages(&tx).await?;
        let mut applicable = HashSet::new();

        for pkg in described_packages {
            applicable.extend(
                self.related_packages_transitively(
                    &[Relationship::DependencyOf, Relationship::ContainedBy],
                    pkg.into(),
                    Transactional::None,
                )
                .await?,
            )
        }

        let mut assertions = HashMap::new();

        for pkg in applicable {
            let package_assertions = pkg.vulnerability_assertions(&tx).await?;
            if !package_assertions.assertions.is_empty() {
                assertions.insert(pkg.clone(), pkg.vulnerability_assertions(&tx).await?);
            }
        }

        Ok(assertions)
    }

    /*

    pub async fn direct_dependencies(&self, tx: Transactional<'_>) -> Result<Vec<Purl>, Error> {
        let found = package::Entity::find()
            .join(
                JoinType::LeftJoin,
                sbom_dependency::Relation::Package.def().rev(),
            )
            .filter(sbom_dependency::Column::SbomId.eq(self.sbom.id))
            .find_with_related(package_qualifier::Entity)
            .all(&self.graph.connection(tx))
            .await?;

        Ok(packages_to_purls(found)?)
    }

     */
}

#[cfg(test)]
mod tests {
    use crate::graph::Graph;
    use test_log::test;
    use trustify_common::db::{Database, Transactional};
    use trustify_common::purl::Purl;
    use trustify_common::sbom::SbomLocator;
    use trustify_entity::relationship::Relationship;

    #[test(tokio::test)]
    async fn ingest_sboms() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_sboms").await?;
        let system = Graph::new(db);

        let sbom_v1 = system
            .ingest_sbom("http://sbom.com/test.json", "8", Transactional::None)
            .await?;
        let sbom_v1_again = system
            .ingest_sbom("http://sbom.com/test.json", "8", Transactional::None)
            .await?;
        let sbom_v2 = system
            .ingest_sbom("http://sbom.com/test.json", "9", Transactional::None)
            .await?;

        let other_sbom = system
            .ingest_sbom("http://sbom.com/other.json", "10", Transactional::None)
            .await?;

        assert_eq!(sbom_v1.sbom.id, sbom_v1_again.sbom.id);

        assert_ne!(sbom_v1.sbom.id, sbom_v2.sbom.id);
        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_and_fetch_sboms_describing_purls() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_and_fetch_sboms_describing_purls").await?;
        let system = Graph::new(db);

        let sbom_v1 = system
            .ingest_sbom("http://sbom.com/test.json", "8", Transactional::None)
            .await?;
        let sbom_v2 = system
            .ingest_sbom("http://sbom.com/test.json", "9", Transactional::None)
            .await?;
        let sbom_v3 = system
            .ingest_sbom("http://sbom.com/test.json", "10", Transactional::None)
            .await?;

        sbom_v1
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom_v2
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom_v3
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.9.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let found = system
            .locate_sboms(
                SbomLocator::Purl("pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?),
                Transactional::None,
            )
            .await?;

        assert_eq!(2, found.len());
        assert!(found.contains(&sbom_v1));
        assert!(found.contains(&sbom_v2));

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_and_locate_sboms_describing_cpes() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_and_locate_sboms_describing_cpes").await?;
        let system = Graph::new(db);

        let sbom_v1 = system
            .ingest_sbom("http://sbom.com/test.json", "8", Transactional::None)
            .await?;
        let sbom_v2 = system
            .ingest_sbom("http://sbom.com/test.json", "9", Transactional::None)
            .await?;
        let sbom_v3 = system
            .ingest_sbom("http://sbom.com/test.json", "10", Transactional::None)
            .await?;

        sbom_v1
            .ingest_describes_cpe22(
                cpe::uri::Uri::parse("cpe:/a:redhat:quarkus:2.13::el8")?,
                Transactional::None,
            )
            .await?;

        sbom_v2
            .ingest_describes_cpe22(
                cpe::uri::Uri::parse("cpe:/a:redhat:quarkus:2.13::el8")?,
                Transactional::None,
            )
            .await?;

        sbom_v3
            .ingest_describes_cpe22(
                cpe::uri::Uri::parse("cpe:/a:redhat:not-quarkus:2.13::el8")?,
                Transactional::None,
            )
            .await?;

        let found = system
            .locate_sboms(
                SbomLocator::Cpe(cpe::uri::Uri::parse("cpe:/a:redhat:quarkus:2.13::el8")?.into()),
                Transactional::None,
            )
            .await?;

        assert_eq!(2, found.len());
        assert!(found.contains(&sbom_v1));
        assert!(found.contains(&sbom_v2));

        Ok(())
    }

    #[test(tokio::test)]
    async fn transitive_dependency_of() -> Result<(), anyhow::Error> {
        let db = Database::for_test("transitive_dependency_of").await?;
        let system = Graph::new(db);

        let sbom1 = system
            .ingest_sbom(
                "http://sbomsRus.gov/thing1.json",
                "8675309",
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/transitive-b@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/transitive-a@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/transitive-c@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/transitive-b@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/transitive-d@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/transitive-c@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/transitive-e@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/transitive-c@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/transitive-d@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/transitive-b@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let results = sbom1
            .related_packages_transitively(
                &[Relationship::DependencyOf],
                "pkg://maven/io.quarkus/transitive-a@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        Ok(())
    }

    #[test(tokio::test)]
    async fn ingest_package_relates_to_package_dependency_of() -> Result<(), anyhow::Error> {
        let db = Database::for_test("ingest_contains_packages").await?;
        let system = Graph::new(db);

        let sbom1 = system
            .ingest_sbom(
                "http://sbomsRus.gov/thing1.json",
                "8675309",
                Transactional::None,
            )
            .await?;

        sbom1
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/quarkus-postgres@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let sbom2 = system
            .ingest_sbom(
                "http://sbomsRus.gov/thing2.json",
                "8675308",
                Transactional::None,
            )
            .await?;

        sbom2
            .ingest_package_relates_to_package(
                "pkg://maven/io.quarkus/quarkus-sqlite@1.2.3".try_into()?,
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        let dependencies = sbom1
            .related_packages(
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        assert_eq!(1, dependencies.len());

        assert_eq!(
            "pkg://maven/io.quarkus/quarkus-postgres@1.2.3",
            Purl::from(dependencies[0].clone()).to_string()
        );

        let dependencies = sbom2
            .related_packages(
                Relationship::DependencyOf,
                "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
                Transactional::None,
            )
            .await?;

        assert_eq!(1, dependencies.len());

        assert_eq!(
            "pkg://maven/io.quarkus/quarkus-sqlite@1.2.3",
            Purl::from(dependencies[0].clone()).to_string()
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn sbom_vulnerabilities() -> Result<(), anyhow::Error> {
        let db = Database::for_test("sbom_vulnerabilities").await?;
        let system = Graph::new(db);

        println!("{:?}", system);

        let sbom = system
            .ingest_sbom(
                "http://sbomsRus.gov/thing1.json",
                "8675309",
                Transactional::None,
            )
            .await?;

        println!("-------------------- A");

        sbom.ingest_describes_package("pkg://oci/my-app@1.2.3".try_into()?, Transactional::None)
            .await?;
        println!("-------------------- B");

        sbom.ingest_package_relates_to_package(
            "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Relationship::DependencyOf,
            "pkg://oci/my-app@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;
        println!("-------------------- C");

        sbom.ingest_package_relates_to_package(
            "pkg://maven/io.quarkus/quarkus-postgres@1.2.3".try_into()?,
            Relationship::DependencyOf,
            "pkg://maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;
        println!("-------------------- D");

        sbom.ingest_package_relates_to_package(
            "pkg://maven/postgres/postgres-driver@1.2.3".try_into()?,
            Relationship::DependencyOf,
            "pkg://maven/io.quarkus/quarkus-postgres@1.2.3".try_into()?,
            Transactional::None,
        )
        .await?;

        let advisory = system
            .ingest_advisory(
                "RHSA-1",
                "http://redhat.com/secdata/RHSA-1",
                "7",
                Transactional::None,
            )
            .await?;

        let advisory_vulnerability = advisory
            .link_to_vulnerability("CVE-00000001", Transactional::None)
            .await?;

        advisory_vulnerability
            .ingest_affected_package_range(
                "pkg://maven/postgres/postgres-driver".try_into()?,
                "1.1",
                "1.9",
                Transactional::None,
            )
            .await?;

        let assertions = sbom.vulnerability_assertions(Transactional::None).await?;

        assert_eq!(1, assertions.len());

        let affected_purls = assertions
            .keys()
            .map(|e| Purl::from(e.clone()))
            .collect::<Vec<_>>();

        assert_eq!(
            affected_purls[0].to_string(),
            "pkg://maven/postgres/postgres-driver@1.2.3"
        );

        Ok(())
    }

    /*
    #[tokio::test]
    async fn ingest_contains_packages() -> Result<(), anyhow::Error> {
        env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .init();

            let graph = InnerSystem::for_test("ingest_contains_packages").await?;

            let sbom = graph
                .ingest_sbom("http://sboms.mobi/something.json", "7", Transactional::None)
                .await?;

            let contains1 = sbom
                .ingest_contains_package(
                    "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                    Transactional::None,
                )
                .await?;

            let contains2 = sbom
                .ingest_contains_package(
                    "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                    Transactional::None,
                )
                .await?;

            let contains3 = sbom
                .ingest_contains_package(
                    "pkg://maven/io.quarkus/quarkus-addons@1.2.3",
                    Transactional::None,
                )
                .await?;

            assert_eq!(
                contains1.sbom_contains_package.qualified_package_id,
                contains2.sbom_contains_package.qualified_package_id
            );
            assert_ne!(
                contains1.sbom_contains_package.qualified_package_id,
                contains3.sbom_contains_package.qualified_package_id
            );

            let mut contains = sbom.contains_packages(Transactional::None).await?;

            assert_eq!(2, contains.len());

            let contains: Vec<_> = contains.drain(0..).map(Purl::from).collect();

            assert!(contains.contains(&Purl::from("pkg://maven/io.quarkus/quarkus-core@1.2.3")));
            assert!(contains.contains(&Purl::from("pkg://maven/io.quarkus/quarkus-addons@1.2.3")));

            Ok(())
        }
         */

    /*

    #[tokio::test]
    async fn ingest_and_fetch_sbom_packages() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .init();

         */
        let graph = InnerSystem::for_test("ingest_and_fetch_sbom_packages").await?;

        let sbom_v1 = graph.ingest_sbom("http://sbom.com/test.json", "8").await?;
        let sbom_v2 = graph.ingest_sbom("http://sbom.com/test.json", "9").await?;
        let sbom_v3 = graph
            .ingest_sbom("http://sbom.com/test.json", "10")
            .await?;

        sbom_v1
            .ingest_sbom_dependency("pkg://maven/io.quarkus/taco@1.2.3", Transactional::None)
            .await?;

        sbom_v1
            .ingest_package_dependency(
                "pkg://maven/io.quarkus/foo@1.2.3",
                "pkg://maven/io.quarkus/baz@1.2.3",
                Transactional::None,
            )
            .await?;

        sbom_v2
            .ingest_package_dependency(
                "pkg://maven/io.quarkus/foo@1.2.3",
                "pkg://maven/io.quarkus/bar@1.2.3",
                Transactional::None,
            )
            .await?;

        let sbom_packages = sbom_v1.all_packages(Transactional::None).await?;
        assert_eq!(3, sbom_packages.len());

        for sbom_package in sbom_packages {
            let _sboms = sbom_package
                .package
                .sboms_containing(Transactional::None)
                .await?;
        }

        Ok(())
    }

     */
}
