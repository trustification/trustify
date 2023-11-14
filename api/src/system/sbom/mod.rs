//! Support for SBOMs.

use std::collections::hash_set::Union;
use crate::db::Transactional;
use crate::system::package::package_version::PackageVersionContext;
use crate::system::package::qualified_package::QualifiedPackageContext;
use crate::system::package::PackageContext;
use crate::system::InnerSystem;
use huevos_common::purl::Purl;
use huevos_common::sbom::{SbomLocator};
use huevos_entity as entity;
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, ModelTrait, QueryFilter, QueryResult, QuerySelect, QueryTrait, RelationTrait, Select, Set, TransactionTrait};
use sea_query::{Condition, JoinType, Query, UnionType};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use huevos_entity::relationship::Relationship;

use super::error::Error;


type SelectEntity<E> = Select<E>;

pub enum SbomDescribes {
    Cpe(String),
    Package(SbomPackageContext)
}

impl FromQueryResult for SbomDescribes {
    fn from_query_result(res: &QueryResult, pre: &str) -> Result<Self, DbErr> {
        todo!()
    }
}



impl InnerSystem {
    pub async fn get_sbom(
        &self,
        location: &str,
        sha256: &str,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(entity::sbom::Entity::find()
            .filter(Condition::all().add(entity::sbom::Column::Location.eq(location.clone())))
            .filter(Condition::all().add(entity::sbom::Column::Sha256.eq(sha256.to_string())))
            .one(&self.db)
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    pub async fn ingest_sbom(
        &self,
        location: &str,
        sha256: &str,
        tx: Transactional<'_>,
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
    /// may exist in the system in actuality.
    ///
    /// If the requested SBOM does not exist in the system, it will not exist
    /// after this query either. This function is *non-mutating*.
    pub async fn locate_sbom(
        &self,
        sbom_locator: SbomLocator,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        match sbom_locator {
            SbomLocator::Id(id) => self.locate_sbom_by_id(id, tx).await,
            SbomLocator::Location(location) => self.locate_sbom_by_location(&location, tx).await,
            SbomLocator::Sha256(sha256) => self.locate_sbom_by_sha256(&sha256, tx).await,
            SbomLocator::Purl(purl) => self.locate_sbom_by_purl(purl, tx).await,
            SbomLocator::Cpe(cpe) => self.locate_sbom_by_cpe(&cpe, tx).await,
        }
    }

    pub async fn locate_sboms(
        &self,
        sbom_locator: SbomLocator,
        tx: Transactional<'_>,
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
            SbomLocator::Cpe(cpe) => self.locate_sboms_by_cpe(&cpe, tx).await,
            _ => todo!(),
        }
    }

    async fn locate_one_sbom(
        &self,
        query: SelectEntity<entity::sbom::Entity>,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(query
            .one(&self.connection(tx))
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    async fn locate_many_sboms(
        &self,
        query: SelectEntity<entity::sbom::Entity>,
        tx: Transactional<'_>,
    ) -> Result<Vec<SbomContext>, Error> {
        println!("QUERY {:?}", query.build(self.db.get_database_backend()));
        Ok(query
            .all(&self.connection(tx))
            .await?
            .drain(0..)
            .map(|sbom| (self, sbom).into())
            .collect())
    }

    async fn locate_sbom_by_id(
        &self,
        id: i32,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        let query = entity::sbom::Entity::find_by_id(id);
        Ok(entity::sbom::Entity::find_by_id(id)
            .one(&self.connection(tx))
            .await?
            .map(|sbom| (self, sbom).into()))
    }

    async fn locate_sbom_by_location(
        &self,
        location: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            entity::sbom::Entity::find().filter(entity::sbom::Column::Location.eq(location.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sboms_by_location(
        &self,
        location: &str,
        tx: Transactional<'_>,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            entity::sbom::Entity::find().filter(entity::sbom::Column::Location.eq(location.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sbom_by_sha256(
        &self,
        sha256: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            entity::sbom::Entity::find().filter(entity::sbom::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sboms_by_sha256(
        &self,
        sha256: &str,
        tx: Transactional<'_>,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            entity::sbom::Entity::find().filter(entity::sbom::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sbom_by_purl(
        &self,
        purl: Purl,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, tx).await?;

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
                tx,
            )
            .await
        } else {
            Ok(None)
        }
    }

    async fn locate_sboms_by_purl(
        &self,
        purl: Purl,
        tx: Transactional<'_>,
    ) -> Result<Vec<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, tx).await?;

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
                tx,
            )
            .await
        } else {
            Ok(vec![])
        }
    }

    async fn locate_sbom_by_cpe(
        &self,
        cpe: &str,
        tx: Transactional<'_>,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            entity::sbom::Entity::find()
                .join(
                    JoinType::LeftJoin,
                    entity::sbom_describes_cpe::Relation::Sbom.def().rev(),
                )
                .filter(entity::sbom_describes_cpe::Column::Cpe.eq(cpe.to_string())),
            tx,
        )
        .await
    }

    async fn locate_sboms_by_cpe(
        &self,
        cpe: &str,
        tx: Transactional<'_>,
    ) -> Result<Vec<SbomContext>, Error> {
        self.locate_many_sboms(
            entity::sbom::Entity::find()
                .join(
                    JoinType::LeftJoin,
                    entity::sbom_describes_cpe::Relation::Sbom.def().rev(),
                )
                .filter(entity::sbom_describes_cpe::Column::Cpe.eq(cpe.to_string())),
            tx,
        )
        .await
    }
}

#[derive(Clone)]
pub struct SbomContext {
    pub(crate) system: InnerSystem,
    pub(crate) sbom: entity::sbom::Model,
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

impl From<(&InnerSystem, entity::sbom::Model)> for SbomContext {
    fn from((system, sbom): (&InnerSystem, entity::sbom::Model)) -> Self {
        Self {
            system: system.clone(),
            sbom,
        }
    }
}

#[derive(Clone)]
pub struct SbomPackageContext {
    pub(crate) sbom: SbomContext,
    pub(crate) package: PackageContext,
}

impl Debug for SbomPackageContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.package.fmt(f)
    }
}

impl From<(&SbomContext, entity::package::Model)> for SbomPackageContext {
    fn from((sbom, package): (&SbomContext, entity::package::Model)) -> Self {
        Self {
            sbom: sbom.clone(),
            package: (&sbom.system, package).into(),
        }
    }
}

impl SbomContext {
    pub async fn ingest_describes_cpe(&self, cpe: &str, tx: Transactional<'_>) -> Result<(), Error> {
        let fetch = entity::sbom_describes_cpe::Entity::find()
            .filter(entity::sbom_describes_cpe::Column::SbomId.eq(self.sbom.id))
            .filter(entity::sbom_describes_cpe::Column::Cpe.eq(cpe.to_string()))
            .one(&self.system.connection(tx))
            .await?;

        if fetch.is_none() {
            let model = entity::sbom_describes_cpe::ActiveModel {
                sbom_id: Set(self.sbom.id),
                cpe: Set(cpe.to_string()),
            };

            model.insert(&self.system.connection(tx)).await?;
        }
        Ok(())
    }

    pub async fn ingest_describes_package<P: Into<Purl>>(
        &self,
        package: P,
        tx: Transactional<'_>,
    ) -> Result<(), Error> {
        let fetch = entity::sbom_describes_package::Entity::find()
            .filter(Condition::all().add(entity::sbom_describes_package::Column::SbomId.eq(self.sbom.id)))
            .one(&self.system.connection(tx))
            .await?;

        if fetch.is_none() {
            let package = self
                .system
                .ingest_qualified_package(package.into(), tx)
                .await?;
            let model = entity::sbom_describes_package::ActiveModel {
                sbom_id: Set(self.sbom.id),
                qualified_package_id: Set(package.qualified_package.id),
            };

            model.insert(&self.system.connection(tx)).await?;
        }
        Ok(())
    }

    /// Within the context of *this* SBOM, ingest a relationship between
    /// two packages.
    async fn ingest_package_relates_to_package<P1: Into<Purl>, P2: Into<Purl>>(
        &self,
        left_package: P1,
        relationship: Relationship,
        right_package: P2,
        tx: Transactional<'_>
    ) -> Result<(), Error> {
        let left_package = self.system.ingest_qualified_package(
            left_package,
            tx,
        ).await?;

        let right_package = self.system.ingest_qualified_package(
            right_package,
            tx
        ).await?;

        if entity::package_relates_to_package::Entity::find()
            .filter(
                entity::package_relates_to_package::Column::SbomId.eq( self.sbom.id )
            )
            .filter(
                entity::package_relates_to_package::Column::LeftPackageId.eq( left_package.qualified_package.id)
            )
            .filter(
                entity::package_relates_to_package::Column::Relationship.eq( relationship )
            )
            .filter(
                entity::package_relates_to_package::Column::RightPackageId.eq( right_package.qualified_package.id)
            )
            .one(
                &self.system.connection(tx)
            )
            .await?.is_none() {

            let entity = entity::package_relates_to_package::ActiveModel {
                left_package_id: Set( left_package.qualified_package.id),
                relationship: Set( relationship ),
                right_package_id: Set( right_package.qualified_package.id),
                sbom_id: Set( self.sbom.id )
            };

            entity.insert(
                &self.system.connection(tx)
            ).await?;
        }

        Ok(())
    }

    async fn all_packages(&self, tx: Transactional<'_>) -> Result<Vec<SbomPackageContext>, Error> {
        todo!()
    }

    /*

    async fn ingest_spdx(&self, sbom_data: SPDX) -> Result<(), anyhow::Error> {
        // FIXME: not sure this is correct. It may be that we need to use `DatabaseTransaction` instead of the `db` field
        let sbom = self.clone();
        let system = self.system.clone();
        self.system
            .db
            .transaction(|tx| {
                Box::pin(async move {
                    let tx: Transactional = tx.into();
                    // For each thing described in the SBOM data, link it up to an sbom_cpe or sbom_package.
                    for described in &sbom_data.document_creation_information.document_describes {
                        if let Some(described_package) = sbom_data
                            .package_information
                            .iter()
                            .find(|each| each.package_spdx_identifier.eq(described))
                        {
                            for reference in &described_package.external_reference {
                                if reference.reference_type == "purl" {
                                    sbom.ingest_describes_package(
                                        reference.reference_locator.clone(),
                                        tx.clone(),
                                    )
                                    .await?;
                                } else if reference.reference_type == "cpe22Type" {
                                    sbom.ingest_describes_cpe(
                                        &reference.reference_locator,
                                        tx.clone(),
                                    )
                                    .await?;
                                }
                            }

                            // Add any first-order dependencies from SBOM->purl
                            for described_reference in &described_package.external_reference {
                                for relationship in
                                    &sbom_data.relationships_for_related_spdx_id(described)
                                {
                                    if relationship.relationship_type
                                        == RelationshipType::ContainedBy
                                    {
                                        if let Some(package) =
                                            sbom_data.package_information.iter().find(|each| {
                                                each.package_spdx_identifier
                                                    == relationship.spdx_element_id
                                            })
                                        {
                                            for reference in &package.external_reference {
                                                if reference.reference_type == "purl" {
                                                    sbom.ingest_sbom_dependency(
                                                        reference.reference_locator.clone(),
                                                        tx.clone(),
                                                    )
                                                    .await?;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // connect all other tree-ish package trees in the context of this sbom.
                            for package_info in &sbom_data.package_information {
                                let package_identifier = &package_info.package_spdx_identifier;
                                for package_ref in &package_info.external_reference {
                                    if package_ref.reference_type == "purl" {
                                        let package_context = system
                                            .ingest_package(&package_ref.reference_locator, tx)
                                            .await?;

                                        for relationship in sbom_data
                                            .relationships_for_related_spdx_id(&package_identifier)
                                        {
                                            if relationship.relationship_type
                                                == RelationshipType::ContainedBy
                                            {
                                                if let Some(package) = sbom_data
                                                    .package_information
                                                    .iter()
                                                    .find(|each| {
                                                        each.package_spdx_identifier
                                                            == relationship.spdx_element_id
                                                    })
                                                {
                                                    for reference in &package.external_reference {
                                                        if reference.reference_type == "purl" {
                                                            sbom.ingest_package_dependency(
                                                                package_ref
                                                                    .reference_locator
                                                                    .clone(),
                                                                reference.reference_locator.clone(),
                                                                tx.clone(),
                                                            )
                                                            .await?;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Ok::<(), Error>(())
                })
            })
            .await?;

        /*
        println!("DESCRIBES {:?}", describes);

        println!("--------packages--");
        for pkg in &sbom.package_information {
            for reference in &pkg.external_reference {
                if reference.reference_type == "purl" {
                    println!("{:#?}", reference.reference_locator);
                    package_system.ingest_package(
                        &*reference.reference_locator
                    ).await?;
                }
            }
        }

         */

        Ok(())
    }

    pub async fn direct_dependencies(&self, tx: Transactional<'_>) -> Result<Vec<Purl>, Error> {
        let found = package::Entity::find()
            .join(
                JoinType::LeftJoin,
                sbom_dependency::Relation::Package.def().rev(),
            )
            .filter(sbom_dependency::Column::SbomId.eq(self.sbom.id))
            .find_with_related(package_qualifier::Entity)
            .all(&self.system.connection(tx))
            .await?;

        Ok(packages_to_purls(found)?)
    }

     */
}

#[cfg(test)]
mod tests {
    use crate::db::Transactional;
    use crate::system::InnerSystem;
    use huevos_common::purl::Purl;
    use huevos_common::sbom::SbomLocator;
    use huevos_entity::relationship::Relationship;

    #[tokio::test]
    async fn ingest_sboms() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_sboms").await?;

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

    #[tokio::test]
    async fn ingest_and_fetch_sboms_describing_purls() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_and_fetch_sboms_describing_purls").await?;

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
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        sbom_v2
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None,
            )
            .await?;

        sbom_v3
            .ingest_describes_package(
                "pkg://maven/io.quarkus/quarkus-core@1.9.3",
                Transactional::None,
            )
            .await?;

        let found = system
            .locate_sboms(
                SbomLocator::Purl("pkg://maven/io.quarkus/quarkus-core@1.2.3".into()),
                Transactional::None,
            )
            .await?;

        assert_eq!(2, found.len());
        assert!(found.contains(&sbom_v1));
        assert!(found.contains(&sbom_v2));

        Ok(())
    }

    #[tokio::test]
    async fn ingest_and_locate_sboms_describing_cpes() -> Result<(), anyhow::Error> {
        /*
        env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .init();
         */

        let system = InnerSystem::for_test("ingest_and_locate_sboms_describing_cpes").await?;

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
            .ingest_describes_cpe("cpe:thingy", Transactional::None)
            .await?;

        sbom_v2
            .ingest_describes_cpe("cpe:thingy", Transactional::None)
            .await?;

        sbom_v3
            .ingest_describes_cpe("cpe:other_thingy", Transactional::None)
            .await?;

        let found = system
            .locate_sboms(SbomLocator::Cpe("cpe:thingy".into()), Transactional::None)
            .await?;

        assert_eq!(2, found.len());
        assert!(found.contains(&sbom_v1));
        assert!(found.contains(&sbom_v2));

        Ok(())
    }

    #[tokio::test]
    async fn ingest_package_relates_to_package_dependency_of() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("ingest_contains_packages").await?;

        let sbom = system.ingest_sbom(
            "http://sbomsRus.gov/thing.json",
            "8675309",
            Transactional::None,
        ).await?;

        sbom.ingest_package_relates_to_package(
            "pkg://maven/io.quarkus/quarkus-postgres@1.2.3",
            Relationship::DependencyOf,
            "pkg://maven/io.quarkus/quarkus-core@1.2.3",
                Transactional::None
        ).await?;

        Ok(())

    }


    /*
#[tokio::test]
async fn ingest_contains_packages() -> Result<(), anyhow::Error> {
    env_logger::builder()
    .filter_level(log::LevelFilter::Info)
    .is_test(true)
    .init();

        let system = InnerSystem::for_test("ingest_contains_packages").await?;

        let sbom = system
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
        let system = InnerSystem::for_test("ingest_and_fetch_sbom_packages").await?;

        let sbom_v1 = system.ingest_sbom("http://sbom.com/test.json", "8").await?;
        let sbom_v2 = system.ingest_sbom("http://sbom.com/test.json", "9").await?;
        let sbom_v3 = system
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

    #[tokio::test]
    async fn parse_spdx() -> Result<(), anyhow::Error> {
        let system = InnerSystem::for_test("parse_spdx").await?;

        let pwd = PathBuf::from_str(env!("PWD"))?;
        let test_data = pwd.join("test-data");

        //let sbom = test_data.join( "openshift-4.13.json");
        let sbom = test_data.join("ubi9-9.2-755.1697625012.json");

        let sbom = File::open(sbom)?;

        let start = Instant::now();
        let sbom_data: SPDX = serde_json::from_reader(sbom)?;
        let parse_time = start.elapsed();

        let start = Instant::now();
        let sbom = system.ingest_sbom("test.com/my-sbom.json", "10").await?;

        sbom.ingest_spdx(sbom_data).await?;
        let ingest_time = start.elapsed();
        let start = Instant::now();

        let deps = sbom.direct_dependencies(Transactional::None).await?;

        println!("{:#?}", deps);

        let query_time = start.elapsed();

        println!("parse {}ms", parse_time.as_millis());
        println!("ingest {}ms", ingest_time.as_millis());
        println!("query {}ms", query_time.as_millis());

        Ok(())
    }

     */
}
