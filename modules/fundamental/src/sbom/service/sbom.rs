use super::SbomService;
use crate::{
    sbom::model::{SbomPackage, SbomPackageReference, SbomPackageRelation, SbomSummary, Which},
    Error,
};
use futures_util::{stream, StreamExt, TryStreamExt};
use sea_orm::{
    prelude::Uuid, ColumnTrait, EntityTrait, FromQueryResult, IntoSimpleExpr, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Select, SelectColumns,
};
use sea_query::extension::postgres::PgExpr;
use sea_query::{Expr, Func, JoinType, SimpleExpr};
use serde::Deserialize;
use serde_json::Value;
use std::fmt::Debug;
use tracing::instrument;
use trustify_common::id::TrySelectForId;
use trustify_common::{
    cpe::Cpe,
    db::{
        limiter::{limit_selector, LimiterTrait},
        query::{Filtering, IntoColumns, Query},
        ArrayAgg, JsonBuildObject, ToJson, Transactional,
    },
    id::Id,
    model::{Paginated, PaginatedResults},
    purl::Purl,
};
use trustify_entity::labels::Labels;
use trustify_entity::{
    cpe::{self, CpeDto},
    package, package_relates_to_package, package_version,
    qualified_package::{self, Qualifiers},
    relationship::Relationship,
    sbom::{self, SbomNodeLink},
    sbom_node, sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref,
};

impl SbomService {
    /// fetch one sbom
    pub async fn fetch_sbom<TX: AsRef<Transactional>>(
        &self,
        id: Id,
        tx: TX,
    ) -> Result<Option<SbomSummary>, Error> {
        let connection = self.db.connection(&tx);

        let select = sbom::Entity::find().try_filter(id)?;

        Ok(
            match select
                .find_also_linked(SbomNodeLink)
                .one(&connection)
                .await?
            {
                Some(row) => self.build_summary(row, &tx).await?,
                None => None,
            },
        )
    }

    /// fetch all SBOMs
    pub async fn fetch_sboms<TX: AsRef<Transactional>>(
        &self,
        search: Query,
        paginated: Paginated,
        labels: impl Into<Labels>,

        tx: TX,
    ) -> Result<PaginatedResults<SbomSummary>, Error> {
        let connection = self.db.connection(&tx);
        let labels = labels.into();

        let mut query = sbom::Entity::find().filtering(search)?;

        if !labels.is_empty() {
            query = query.filter(Expr::col(sbom::Column::Labels).contains(labels));
        }

        let limiter = query.find_also_linked(SbomNodeLink).limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;
        let sboms = limiter.fetch().await?;

        let tx = tx.as_ref();
        let items = stream::iter(sboms.into_iter())
            .then(|row| async move { self.build_summary(row, &tx).await })
            .try_filter_map(futures_util::future::ok)
            .try_collect()
            .await?;

        Ok(PaginatedResults { total, items })
    }

    /// turn an (sbom, sbom_node) row into an [`SbomSummary`], if possible
    async fn build_summary(
        &self,
        (sbom, node): (sbom::Model, Option<sbom_node::Model>),
        tx: impl AsRef<Transactional>,
    ) -> Result<Option<SbomSummary>, Error> {
        // TODO: consider improving the n-select issue here
        let described_by = self
            .describes_packages(sbom.sbom_id, Paginated::default(), tx)
            .await?
            .items;

        Ok(match node {
            Some(node) => Some(SbomSummary {
                id: sbom.sbom_id,
                hashes: vec![Id::Sha256(sbom.sha256)],
                document_id: sbom.document_id,

                name: node.name,
                published: sbom.published,
                authors: sbom.authors,

                described_by,
                labels: sbom.labels,
            }),
            None => None,
        })
    }

    /// Fetch all packages from an SBOM.
    ///
    /// If you need to find packages based on their relationship, even in the relationship to
    /// SBOM itself, use [`Self::fetch_related_packages`].
    #[instrument(skip(self, tx), err)]
    pub async fn fetch_sbom_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        search: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackage>, Error> {
        #[derive(FromQueryResult)]
        struct Row {
            id: String,
            name: String,
            version: Option<String>,
            purls: Vec<Value>,
            cpes: Vec<Value>,
        }

        let db = self.db.connection(&tx);

        let mut query = sbom_package::Entity::find()
            .filter(sbom_package::Column::SbomId.eq(sbom_id))
            .join(JoinType::Join, sbom_package::Relation::Node.def())
            .select_only()
            .column_as(sbom_package::Column::NodeId, "id")
            .group_by(sbom_package::Column::NodeId)
            .column_as(sbom_package::Column::Version, "version")
            .group_by(sbom_package::Column::Version)
            .column_as(sbom_node::Column::Name, "name")
            .group_by(sbom_node::Column::Name)
            .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def());

        query = join_purls_and_cpes(query)
            .filtering_with(
                search,
                sbom_package::Entity
                    .columns()
                    .add_columns(sbom_node::Entity)
                    .add_columns(package::Entity)
                    .add_columns(sbom_package_cpe_ref::Entity)
                    .add_columns(sbom_package_purl_ref::Entity),
            )?
            .order_by_asc(sbom_package::Column::NodeId); // default order

        // limit and execute

        let limiter =
            limit_selector::<'_, _, _, _, Row>(&db, query, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let packages = limiter.fetch().await?;

        // collect results

        let items = packages
            .into_iter()
            .map(
                |Row {
                     id,
                     name,
                     version,
                     purls,
                     cpes,
                 }| package_from_row(id, name, version, purls, cpes),
            )
            .collect();

        Ok(PaginatedResults { items, total })
    }

    /// Get all packages describing the SBOM.
    #[instrument(skip(self, tx), err)]
    pub async fn describes_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackage>, Error> {
        self.fetch_related_packages(
            sbom_id,
            Default::default(),
            paginated,
            Which::Right,
            SbomPackageReference::Root,
            Some(Relationship::DescribedBy),
            tx,
        )
        .await
        .map(|r| r.map(|rel| rel.package))
    }

    #[instrument(skip(self, tx), err)]
    pub async fn find_related_sboms(
        &self,
        qualified_package_id: Uuid,
        paginated: Paginated,
        query: Query,
        tx: impl AsRef<Transactional>,
    ) -> Result<PaginatedResults<SbomSummary>, Error> {
        let db = self.db.connection(&tx);

        let query = sbom::Entity::find()
            .join(JoinType::Join, sbom::Relation::Packages.def())
            .join(JoinType::Join, sbom_package::Relation::Purl.def())
            .filter(sbom_package_purl_ref::Column::QualifiedPackageId.eq(qualified_package_id))
            .filtering(query)?
            .find_also_linked(SbomNodeLink);

        // limit and execute

        let limiter = query.limiting(&db, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let sboms = limiter.fetch().await?;

        // collect results

        let tx = tx.as_ref();
        let items = stream::iter(sboms.into_iter())
            .then(|row| async move { self.build_summary(row, &tx).await })
            .try_filter_map(futures_util::future::ok)
            .try_collect()
            .await?;

        Ok(PaginatedResults { items, total })
    }

    /// Fetch all related packages in the context of an SBOM.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, tx), err)]
    pub async fn fetch_related_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        search: Query,
        paginated: Paginated,
        which: Which,
        reference: impl Into<SbomPackageReference<'_>> + Debug,
        relationship: Option<Relationship>,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackageRelation>, Error> {
        let db = self.db.connection(&tx);

        // which way

        log::debug!("Which: {which:?}");

        // select all qualified packages for which we have relationships

        let (filter, join) = match which {
            Which::Left => (
                package_relates_to_package::Column::LeftNodeId,
                package_relates_to_package::Relation::Right,
            ),
            Which::Right => (
                package_relates_to_package::Column::RightNodeId,
                package_relates_to_package::Relation::Left,
            ),
        };

        #[derive(FromQueryResult)]
        struct Row {
            id: String,
            relationship: Relationship,
            name: String,
            version: Option<String>,
            purls: Vec<Value>,
            cpes: Vec<Value>,
        }

        let mut query = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(sbom_id))
            .select_only()
            .select_column_as(sbom_node::Column::NodeId, "id")
            .group_by(sbom_node::Column::NodeId)
            .select_column_as(sbom_node::Column::Name, "name")
            .group_by(sbom_node::Column::Name)
            .select_column_as(
                package_relates_to_package::Column::Relationship,
                "relationship",
            )
            .group_by(package_relates_to_package::Column::Relationship)
            .select_column_as(sbom_package::Column::Version, "version")
            .group_by(sbom_package::Column::Version)
            // join the other side
            .join(JoinType::Join, join.def())
            .join(JoinType::Join, sbom_node::Relation::Package.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def());

        // collect PURLs and CPEs

        query = join_purls_and_cpes(query);

        // filter for reference

        query = match reference.into() {
            SbomPackageReference::Root => {
                // sbom - add join to sbom table
                query.join(JoinType::Join, sbom_node::Relation::Sbom.def())
            }
            SbomPackageReference::Package(node_id) => {
                // package - set node id filter
                query.filter(filter.eq(node_id))
            }
        };

        // apply filter conditions

        query = query.filtering(search)?;

        // add relationship type filter

        if let Some(relationship) = relationship {
            query = query.filter(package_relates_to_package::Column::Relationship.eq(relationship));
        }

        // limit and execute

        let limiter =
            limit_selector::<'_, _, _, _, Row>(&db, query, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let packages = limiter.fetch().await?;

        // collect results

        let items = packages
            .into_iter()
            .map(
                |Row {
                     id,
                     relationship,
                     name,
                     version,
                     purls,
                     cpes,
                 }| SbomPackageRelation {
                    package: package_from_row(id, name, version, purls, cpes),
                    relationship,
                },
            )
            .collect();

        Ok(PaginatedResults { items, total })
    }

    /// A simplified version of [`Self::fetch_related_packages`].
    ///
    /// It uses [`Which::Right`] and the provided reference, [`Default::default`] for the rest.
    pub async fn related_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        relationship: Relationship,
        pkg: impl Into<SbomPackageReference<'_>> + Debug,
        tx: TX,
    ) -> Result<Vec<SbomPackage>, Error> {
        let result = self
            .fetch_related_packages(
                sbom_id,
                Default::default(),
                Default::default(),
                Which::Right,
                pkg,
                Some(relationship),
                tx,
            )
            .await?;

        Ok(result.items.into_iter().map(|r| r.package).collect())
    }
}

/// Join CPE and PURL information.
///
/// Given a select over something which already joins sbom_package_purl_ref and
/// sbom_package_cpe_ref, this adds joins to fetch the data for PURLs and CPEs so that it can be
/// built using [`package_from_row`].
///
/// This will add the columns `purls` and `cpes` to the selected output.
fn join_purls_and_cpes<E>(query: Select<E>) -> Select<E>
where
    E: EntityTrait,
{
    query
        .join(
            JoinType::LeftJoin,
            sbom_package_purl_ref::Relation::Purl.def(),
        )
        .join(
            JoinType::LeftJoin,
            qualified_package::Relation::PackageVersion.def(),
        )
        .join(JoinType::LeftJoin, package_version::Relation::Package.def())
        // aggregate the q -> v -> p hierarchy into an array of json objects
        .select_column_as(
            Expr::cust_with_exprs(
                "coalesce($1 filter (where $2), '{}')",
                [
                    SimpleExpr::from(
                        Func::cust(ArrayAgg).arg(
                            Func::cust(JsonBuildObject)
                                // must match with PurlDto struct
                                .arg("type")
                                .arg(package::Column::Type.into_expr())
                                .arg("name")
                                .arg(package::Column::Name.into_expr())
                                .arg("namespace")
                                .arg(package::Column::Namespace.into_expr())
                                .arg("version")
                                .arg(package_version::Column::Version.into_expr())
                                .arg("qualifiers")
                                .arg(qualified_package::Column::Qualifiers.into_expr()),
                        ),
                    ),
                    sbom_package_purl_ref::Column::QualifiedPackageId
                        .is_not_null()
                        .into_simple_expr(),
                ],
            ),
            "purls",
        )
        .join(
            JoinType::LeftJoin,
            sbom_package_cpe_ref::Relation::Cpe.def(),
        )
        // aggregate the cpe rows into an array of json objects
        .select_column_as(
            Expr::cust_with_exprs(
                "coalesce($1 filter (where $2), '{}')",
                [
                    SimpleExpr::from(
                        Func::cust(ArrayAgg).arg(Func::cust(ToJson).arg(Expr::col(cpe::Entity))),
                    ),
                    sbom_package_cpe_ref::Column::CpeId.is_not_null(),
                ],
            ),
            "cpes",
        )
}

/// Convert values from a "package row" into an SBOM package
fn package_from_row(
    id: String,
    name: String,
    version: Option<String>,
    purls: Vec<Value>,
    cpes: Vec<Value>,
) -> SbomPackage {
    SbomPackage {
        id,
        name,
        version,
        purl: purls
            .into_iter()
            .flat_map(|purl| serde_json::from_value::<PurlDto>(purl).ok())
            .map(Purl::from)
            .map(|purl| purl.to_string())
            .collect(),
        cpe: cpes
            .into_iter()
            .flat_map(|cpe| {
                serde_json::from_value::<CpeDto>(cpe)
                    .inspect_err(|err| {
                        log::warn!("Failed to deserialize CPE: {err}");
                    })
                    .ok()
            })
            .flat_map(|cpe| {
                log::debug!("CPE: {cpe:?}");
                Cpe::try_from(cpe)
                    .inspect_err(|err| {
                        log::warn!("Failed to build CPE: {err}");
                    })
                    .ok()
            })
            .map(|cpe| cpe.to_string())
            .collect(),
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PurlDto {
    r#type: String,
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    version: String,
    qualifiers: Qualifiers,
}

impl From<PurlDto> for Purl {
    fn from(value: PurlDto) -> Self {
        let PurlDto {
            r#type,
            name,
            namespace,
            version,
            qualifiers,
        } = value;
        Self {
            ty: r#type,
            name,
            namespace,
            version: if version.is_empty() {
                None
            } else {
                Some(version)
            },
            qualifiers: qualifiers.0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::query::q;
    use trustify_common::db::test::TrustifyContext;
    use trustify_common::hashing::Digests;
    use trustify_entity::labels::Labels;
    use trustify_module_ingestor::graph::Graph;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn all_sboms(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db.clone());

        let sbom_v1 = system
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-1"),
                "http://redhat.com/test.json",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v1_again = system
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-1"),
                "http://redhat.com/test.json",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v2 = system
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-2"),
                "http://myspace.com/test.json",
                (),
                Transactional::None,
            )
            .await?;

        let _other_sbom = system
            .ingest_sbom(
                Labels::default(),
                &Digests::digest("RHSA-3"),
                "http://geocities.com/other.json",
                (),
                Transactional::None,
            )
            .await?;

        assert_eq!(sbom_v1.sbom.sbom_id, sbom_v1_again.sbom.sbom_id);
        assert_ne!(sbom_v1.sbom.sbom_id, sbom_v2.sbom.sbom_id);

        let fetch = SbomService::new(db);

        let fetched = fetch
            .fetch_sboms(q("MySpAcE"), Paginated::default(), (), ())
            .await?;

        log::debug!("{:#?}", fetched.items);
        assert_eq!(1, fetched.total);

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn labels(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db.clone());

        let _sbom1 = system
            .ingest_sbom(
                Labels::new()
                    .add("source", "test")
                    .add("ci", "job1")
                    .add("team", "a"),
                &Digests::digest("RHSA-1"),
                "http://redhat.com/test1.json",
                (),
                Transactional::None,
            )
            .await?;

        let _sbom2 = system
            .ingest_sbom(
                Labels::new()
                    .add("source", "test")
                    .add("ci", "job2")
                    .add("team", "b"),
                &Digests::digest("RHSA-2"),
                "http://redhat.com/test2.json",
                (),
                Transactional::None,
            )
            .await?;

        let _sbom3 = system
            .ingest_sbom(
                Labels::new()
                    .add("source", "test")
                    .add("ci", "job2")
                    .add("team", "a"),
                &Digests::digest("RHSA-3"),
                "http://redhat.com/test3.json",
                (),
                Transactional::None,
            )
            .await?;

        let service = SbomService::new(db);

        let fetched = service
            .fetch_sboms(Query::default(), Paginated::default(), ("ci", "job1"), ())
            .await?;
        assert_eq!(1, fetched.total);

        let fetched = service
            .fetch_sboms(Query::default(), Paginated::default(), ("ci", "job2"), ())
            .await?;
        assert_eq!(2, fetched.total);

        let fetched = service
            .fetch_sboms(Query::default(), Paginated::default(), ("ci", "job3"), ())
            .await?;
        assert_eq!(0, fetched.total);

        let fetched = service
            .fetch_sboms(Query::default(), Paginated::default(), ("foo", "bar"), ())
            .await?;
        assert_eq!(0, fetched.total);

        let fetched = service
            .fetch_sboms(Query::default(), Paginated::default(), (), ())
            .await?;
        assert_eq!(3, fetched.total);

        let fetched = service
            .fetch_sboms(
                Query::default(),
                Paginated::default(),
                [("ci", "job2"), ("team", "a")],
                (),
            )
            .await?;
        assert_eq!(1, fetched.total);

        Ok(())
    }
}
