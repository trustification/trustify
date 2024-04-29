//! Support for SBOMs.

use super::error::Error;
use crate::db::{LeftPackageId, QualifiedPackageTransitive};
use crate::graph::cpe::CpeContext;
use crate::graph::package::creator::Creator;
use crate::graph::package::package_version::PackageVersionContext;
use crate::graph::package::qualified_package::QualifiedPackageContext;
use crate::graph::package::PackageContext;
use crate::graph::Graph;
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
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::Transactional;
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_common::package::PackageVulnerabilityAssertions;
use trustify_common::purl::Purl;
use trustify_common::sbom::SbomLocator;
use trustify_entity as entity;
use trustify_entity::relationship::Relationship;
use trustify_entity::sbom;
use trustify_module_search::model::SearchOptions;
use trustify_module_search::query::Query as TrustifyQuery;

pub mod spdx;

#[cfg(test)]
mod tests;

#[derive(Clone, Default)]
pub struct SbomInformation {
    pub title: Option<String>,
    pub published: Option<OffsetDateTime>,
}

impl From<()> for SbomInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

type SelectEntity<E> = Select<E>;

impl Graph {
    pub async fn sboms<TX: AsRef<Transactional>>(
        &self,
        search: SearchOptions,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<SbomContext>, Error> {
        let connection = self.connection(&tx);

        let limiter = sbom::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        Ok(PaginatedResults {
            total: limiter.total().await?,
            items: limiter
                .fetch()
                .await?
                .drain(0..)
                .map(|each| SbomContext::new(self, each))
                .collect(),
        })
    }

    pub async fn get_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(entity::sbom::Entity::find_by_id(id)
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
            .filter(Condition::all().add(entity::sbom::Column::Location.eq(location)))
            .filter(Condition::all().add(entity::sbom::Column::Sha256.eq(sha256.to_string())))
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

        let SbomInformation { title, published } = info.into();

        let model = entity::sbom::ActiveModel {
            document_id: Set(document_id.to_string()),
            location: Set(location.to_string()),
            sha256: Set(sha256.to_string()),

            title: Set(title),
            published: Set(published),

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
        query: SelectEntity<entity::sbom::Entity>,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        Ok(query
            .one(&self.connection(&tx))
            .await?
            .map(|sbom| SbomContext::new(self, sbom)))
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
            .map(|sbom| SbomContext::new(self, sbom))
            .collect())
    }

    async fn locate_sbom_by_id<TX: AsRef<Transactional>>(
        &self,
        id: i32,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        let _query = entity::sbom::Entity::find_by_id(id);
        Ok(entity::sbom::Entity::find_by_id(id)
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
        purl: &Purl,
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
        purl: &Purl,
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
    pub graph: Graph,
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

impl SbomContext {
    pub fn new(graph: &Graph, sbom: sbom::Model) -> Self {
        Self {
            graph: graph.clone(),
            sbom,
        }
    }

    #[instrument(skip(tx), err)]
    pub async fn ingest_describes_cpe22<C: Into<Cpe> + Debug, TX: AsRef<Transactional>>(
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

    #[instrument(skip(tx), err)]
    pub async fn ingest_describes_package<TX: AsRef<Transactional>>(
        &self,
        purl: &Purl,
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

    #[instrument(skip(tx), err)]
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
            sbom_id: Set(self.sbom.id),
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
        pkg: &Purl,
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

            let found = entity::qualified_package::Entity::find()
                .filter(entity::qualified_package::Column::Id.in_subquery(related_query))
                .all(&self.graph.connection(&tx))
                .await?;

            let mut related = Vec::new();

            for base in found.into_iter() {
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
                        let package = PackageContext::new(&self.graph, package);
                        let package_version = PackageVersionContext::new(&package, package_version);

                        related.push(QualifiedPackageContext::new(&package_version, base));
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
