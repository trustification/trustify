//! Support for SBOMs.

use super::error::Error;
use crate::db::{LeftPackageId, QualifiedPackageTransitive};
use crate::graph::cpe::CpeContext;
use crate::graph::package::creator::Creator;
use crate::graph::package::package_version::PackageVersionContext;
use crate::graph::package::qualified_package::QualifiedPackageContext;
use crate::graph::package::PackageContext;
use crate::graph::Graph;
use sea_orm::prelude::Uuid;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
    RelationTrait, Select, Set,
};
use sea_query::{Condition, Func, JoinType, OnConflict, Query, SimpleExpr};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::cpe::Cpe;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_common::db::Transactional;
use trustify_common::package::PackageVulnerabilityAssertions;
use trustify_common::purl::Purl;
use trustify_common::sbom::SbomLocator;
use trustify_entity as entity;
use trustify_entity::relationship::Relationship;
use trustify_entity::sbom;

pub mod spdx;

/*
#[cfg(test)]
mod tests;
 */

#[derive(Clone, Default)]
pub struct SbomInformation {
    /// The id of the document in the SBOM graph
    pub node_id: String,
    /// The name of the document/node
    pub name: String,
    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,
}

impl From<()> for SbomInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

type SelectEntity<E> = Select<E>;

impl Graph {
    pub async fn get_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(sbom::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    #[instrument(skip(tx))]
    pub async fn get_sbom<TX: AsRef<Transactional>>(
        &self,
        location: &str,
        sha256: &str,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(entity::sbom::Entity::find()
            .filter(Condition::all().add(sbom::Column::Location.eq(location)))
            .filter(Condition::all().add(sbom::Column::Sha256.eq(sha256.to_string())))
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    #[instrument(skip(tx, info), err)]
    pub async fn ingest_sbom<TX: AsRef<Transactional>>(
        &self,
        location: &str,
        sha256: &str,
        document_id: &str,
        info: impl Into<SbomInformation>,
        tx: TX,
    ) -> Result<SbomContext, Error> {
        if let Some(found) = self.get_sbom(location, sha256, &tx).await? {
            return Ok(found);
        }

        let SbomInformation {
            node_id,
            name,
            published,
            authors,
        } = info.into();

        let model = sbom::ActiveModel {
            sbom_id: Set(Uuid::now_v7()),
            node_id: Set(node_id),
            name: Set(name),

            document_id: Set(document_id.to_string()),
            location: Set(location.to_string()),
            sha256: Set(sha256.to_string()),

            published: Set(published),
            authors: Set(authors),

            ..Default::default()
        };

        Ok(SbomContext::new(
            self,
            model.insert(&self.connection(&tx)).await?,
        ))
    }

    /// Fetch a single SBOM located via internal `id`, external `location` (URL),
    /// described pURL, described CPE, or sha256 hash.
    ///
    /// Fetching by pURL, CPE or location may result in a single result where multiple
    /// may exist in the fetch in actuality.
    ///
    /// If the requested SBOM does not exist in the fetch, it will not exist
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
            SbomLocator::Purl(purl) => self.locate_sbom_by_purl(&purl, tx).await,
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
            SbomLocator::Purl(purl) => self.locate_sboms_by_purl(&purl, tx).await,
            SbomLocator::Cpe(cpe) => self.locate_sboms_by_cpe22(cpe, tx).await,
        }
    }

    async fn locate_one_sbom<TX: AsRef<Transactional>>(
        &self,
        query: SelectEntity<sbom::Entity>,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(query
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    async fn locate_many_sboms<TX: AsRef<Transactional>>(
        &self,
        query: SelectEntity<sbom::Entity>,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        Ok(query
            .all(&self.connection(&tx))
            .await?
            .drain(0..)
            .map(|sbom| SbomContext::new(self, sbom))
            .collect())
    }

    async fn locate_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let _query = sbom::Entity::find_by_id(id);
        Ok(sbom::Entity::find_by_id(id)
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
    }

    async fn locate_sbom_by_location<TX: AsRef<Transactional>>(
        &self,
        location: &str,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        self.locate_one_sbom(
            entity::sbom::Entity::find().filter(sbom::Column::Location.eq(location.to_string())),
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
            entity::sbom::Entity::find().filter(sbom::Column::Location.eq(location.to_string())),
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
            entity::sbom::Entity::find().filter(sbom::Column::Sha256.eq(sha256.to_string())),
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
            entity::sbom::Entity::find().filter(sbom::Column::Sha256.eq(sha256.to_string())),
            tx,
        )
        .await
    }

    fn query_by_purl(package: QualifiedPackageContext) -> Select<entity::sbom::Entity> {
        entity::sbom::Entity::find()
            .join(
                JoinType::LeftJoin,
                entity::sbom_package::Relation::Sbom.def().rev(),
            )
            .join(
                JoinType::Join,
                entity::sbom_package_purl_ref::Relation::Purl.def().rev(),
            )
            .filter(
                entity::sbom_package_purl_ref::Column::QualifiedPackageId
                    .eq(package.qualified_package.id),
            )
    }

    fn query_by_cpe(cpe: CpeContext) -> Select<sbom::Entity> {
        entity::sbom::Entity::find()
            .join(
                JoinType::LeftJoin,
                entity::sbom_package::Relation::Sbom.def().rev(),
            )
            .join(
                JoinType::Join,
                entity::sbom_package_cpe_ref::Relation::Cpe.def().rev(),
            )
            .filter(entity::sbom_package_cpe_ref::Column::CpeId.eq(cpe.cpe.id))
    }

    async fn locate_sbom_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, &tx).await?;

        if let Some(package) = package {
            self.locate_one_sbom(Self::query_by_purl(package), &tx)
                .await
        } else {
            Ok(None)
        }
    }

    async fn locate_sboms_by_purl<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        let package = self.get_qualified_package(purl, &tx).await?;

        if let Some(package) = package {
            self.locate_many_sboms(Self::query_by_purl(package), &tx)
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
            self.locate_one_sbom(Self::query_by_cpe(cpe), &tx).await
        } else {
            Ok(None)
        }
    }

    async fn locate_sboms_by_cpe22<C: Into<Cpe>, TX: AsRef<Transactional>>(
        &self,
        cpe: C,
        tx: TX,
    ) -> Result<Vec<SbomContext>, Error> {
        if let Some(cpe) = self.get_cpe(cpe, &tx).await? {
            self.locate_many_sboms(Self::query_by_cpe(cpe), &tx).await
        } else {
            Ok(vec![])
        }
    }
}

#[derive(Clone)]
pub struct SbomContext {
    pub graph: Graph,
    pub sbom: sbom::Model,
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

impl SbomContext {
    pub fn new(graph: &Graph, sbom: sbom::Model) -> Self {
        Self {
            graph: graph.clone(),
            sbom,
        }
    }

    /*
        /// Get the packages which describe an SBOM
        #[instrument(skip(tx), err)]
        pub async fn describes_packages<TX: AsRef<Transactional>>(
            &self,
            tx: TX,
        ) -> Result<Vec<SbomPackage>, Error> {
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

        /// Get the PURLs which describe an SBOM
        #[instrument(skip(tx), err)]
        pub async fn describes_purls<TX: AsRef<Transactional>>(
            &self,
            tx: TX,
        ) -> Result<Vec<SbomPackage>, Error> {
           self.describes_packages(tx).
        }

        /// Get the CPEs which describe an SBOM
        #[instrument(skip(tx), err)]
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

        #[instrument(skip(tx), err)]
        pub async fn packages<TX: AsRef<Transactional>>(
            &self,
            tx: TX,
        ) -> Result<Vec<QualifiedPackageContext>, Error> {
            self.graph
                .get_qualified_packages_by_query(
                    entity::sbom_package::Entity::find()
                        .select_only()
                        .column(entity::sbom_package::Column::QualifiedPackageId)
                        .filter(entity::sbom_package::Column::SbomId.eq(self.sbom.id))
                        .into_query(),
                    tx,
                )
                .await
        }
    */

    fn create_relationship(
        &self,
        left_package_input: &Purl,
        relationship: Relationship,
        right_package_input: &Purl,
    ) -> entity::package_relates_to_package::ActiveModel {
        let left_package = left_package_input.qualifier_uuid();
        let right_package = right_package_input.qualifier_uuid();

        entity::package_relates_to_package::ActiveModel {
            left_package_id: Set(left_package),
            relationship: Set(relationship),
            right_package_id: Set(right_package),
            sbom_id: Set(self.sbom.sbom_id),
        }
    }

    /// Within the context of *this* SBOM, ingest a relationship between
    /// two packages.
    ///
    /// The packages will be created if they don't yet exist.
    #[instrument(skip(tx), err)]
    async fn ingest_package_relates_to_package<'a, TX: AsRef<Transactional>>(
        &'a self,
        left_package_input: &Purl,
        relationship: Relationship,
        right_package_input: &Purl,
        tx: TX,
    ) -> Result<(), Error> {
        // ensure the packages exist first

        let mut creator = Creator::new();
        creator.add(left_package_input.clone());
        creator.add(right_package_input.clone());
        creator.create(&self.graph.connection(&tx)).await?;

        // now create the relationship

        let rel = self.create_relationship(left_package_input, relationship, right_package_input);

        self.ingest_package_relates_to_package_many(tx, [rel])
            .await?;

        Ok(())
    }

    /// Within the context of *this* SBOM, ingest a relationship between
    /// two packages.
    ///
    /// The packages must already be created.
    #[instrument(skip(tx, entities), err)]
    async fn ingest_package_relates_to_package_many<TX, I>(
        &self,
        tx: TX,
        entities: I,
    ) -> Result<(), Error>
    where
        TX: AsRef<Transactional>,
        I: IntoIterator<Item = entity::package_relates_to_package::ActiveModel>,
    {
        for batch in &entities.into_iter().chunked() {
            entity::package_relates_to_package::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        entity::package_relates_to_package::Column::LeftPackageId,
                        entity::package_relates_to_package::Column::Relationship,
                        entity::package_relates_to_package::Column::RightPackageId,
                        entity::package_relates_to_package::Column::SbomId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec(&self.graph.connection(&tx))
                .await?;
        }

        Ok(())
    }

    pub async fn related_packages_transitively_x<TX: AsRef<Transactional>>(
        &self,
        relationship: Relationship,
        pkg: &Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, &tx).await?;

        if let Some(pkg) = pkg {
            Ok(self
                .graph
                .get_qualified_packages_by_query(
                    Query::select()
                        .column(LeftPackageId)
                        .from_function(
                            Func::cust(QualifiedPackageTransitive).args([
                                self.sbom.sbom_id.into(),
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
        pkg: &Purl,
        tx: TX,
    ) -> Result<Vec<QualifiedPackageContext>, Error> {
        let pkg = self.graph.get_qualified_package(pkg, &tx).await?;

        if let Some(pkg) = pkg {
            let rels: SimpleExpr = SimpleExpr::Custom(format!(
                "array[{}]",
                relationships
                    .iter()
                    .map(|e| (*e as i32).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));

            let sbom_id: SimpleExpr = self.sbom.sbom_id.into();
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

    /*
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
                        &pkg.into(),
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
    */
    /*

    pub async fn direct_dependencies(&self, tx: Transactional<'_>) -> Result<Vec<Purl>, Error> {
        let found = package::Entity::find()
            .join(
                JoinType::LeftJoin,
                sbom_dependency::Relation::Package.def().rev(),
            )
            .filter(sbom_dependency::Column::SbomId.eq(self.sbom.id))
            .find_with_related(package_qualifier::Entity)
            .all(&self.fetch.connection(tx))
            .await?;

        Ok(packages_to_purls(found)?)
    }

     */
}
