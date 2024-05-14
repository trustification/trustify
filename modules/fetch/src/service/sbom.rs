use super::FetchService;
use crate::{
    error::Error,
    model::sbom::{SbomPackage, SbomPackageRelation, SbomSummary},
};
use sea_orm::{
    prelude::{Json, Uuid},
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, IntoSimpleExpr, LoaderTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait, Select, SelectColumns,
    SelectorTrait,
};
use sea_query::{
    extension::postgres::PgExpr, Alias, Expr, Func, Iden, IntoColumnRef, IntoIden, IntoTableRef,
    JoinType, SimpleExpr, SimpleExpr::FunctionCall,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt::{Debug, Write};
use std::iter::{repeat, Flatten, Zip};
use std::vec::IntoIter;
use tracing::instrument;
use trustify_common::{
    cpe::Cpe,
    db::{
        limiter::{self, limit_selector, Limiter, LimiterTrait},
        ArrayAgg, JsonBuildObject, ToJson, Transactional,
    },
    model::{Paginated, PaginatedResults},
    purl::Purl,
};
use trustify_entity::{
    cpe::{self, CpeDto},
    package, package_relates_to_package, package_version, qualified_package,
    qualified_package::Qualifiers,
    relationship::Relationship,
    sbom, sbom_node, sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref,
};
use utoipa::openapi::path::ParameterStyle::Simple;
use trustify_common::db::query::{Query, SearchOptions};

// TODO: think about a way to add CPE and PURLs too
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SbomPackageReference<'a> {
    /// Reference the root of an SBOM
    Root,
    /// Reference a package inside an SBOM, by its node id.
    Package(&'a str),
}

impl<'a> From<&'a str> for SbomPackageReference<'a> {
    fn from(value: &'a str) -> Self {
        Self::Package(value)
    }
}

impl<'a> From<()> for SbomPackageReference<'a> {
    fn from(value: ()) -> Self {
        Self::Root
    }
}

#[derive(Clone, Eq, PartialEq, Default, Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Which {
    /// Originating side
    #[default]
    Left,
    /// Target side
    Right,
}

impl FetchService {
    /// fetch all SBOMs
    pub async fn fetch_sboms<TX: AsRef<Transactional>>(
        &self,
        search: SearchOptions,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<SbomSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = sbom::Entity::find()
            .filtering(search)?
            .find_also_related(sbom_node::Entity)
            .limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let sboms = limiter.fetch().await?;

        let mut items = Vec::with_capacity(sboms.len());
        for (sbom, node) in sboms {
            if let Some(node) = node {
                items.push(SbomSummary {
                    id: sbom.sbom_id,
                    sha256: sbom.sha256,
                    document_id: sbom.document_id,

                    name: node.name,
                    published: sbom.published,
                    authors: sbom.authors,
                })
            }
        }

        Ok(PaginatedResults { total, items })
    }

    /// Fetch all packages from an SBOM.
    ///
    /// If you need to find packages based on their relationship, even in the relationship to
    /// SBOM itself, use [`Self::fetch_related_packages`].
    #[instrument(skip(self, tx), err)]
    pub async fn fetch_sbom_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        search: SearchOptions,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackage>, Error> {
        let connection = self.db.connection(&tx);

        #[derive(FromQueryResult)]
        struct Row {
            id: String,
            name: String,
            purls: Vec<Value>,
            cpes: Vec<Value>,
        }

        let mut query = sbom_package::Entity::find()
            .filter(sbom_package::Column::SbomId.eq(sbom_id))
            .join(JoinType::Join, sbom_package::Relation::Node.def())
            .select_only()
            .column_as(sbom_package::Column::NodeId, "id")
            .group_by(sbom_package::Column::NodeId)
            .column_as(sbom_node::Column::Name, "name")
            .group_by(sbom_node::Column::Name)
            .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def());

        let query = join_purls_and_cpes(query);

        // FIXME: disabled due to https://github.com/trustification/trustify/issues/291
        // let mut query = query.filtering(search)?;

        // default order

        let query = query.order_by_asc(sbom_package::Column::NodeId);

        // limit and execute

        let limiter =
            limit_selector::<'_, _, _, _, Row>(&self.db, query, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let packages = limiter.fetch().await?;

        // collect results

        let items = packages
            .into_iter()
            .map(
                |Row {
                     id,
                     name,
                     purls,
                     cpes,
                 }| package_from_row(id, name, purls, cpes),
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
            Which::Left,
            SbomPackageReference::Root,
            Some(Relationship::DescribedBy),
            tx,
        )
        .await
        .map(|r| r.map(|rel| rel.package))
    }

    /// Fetch all related packages in the context of an SBOM.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, tx), err)]
    pub async fn fetch_related_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        search: SearchOptions,
        paginated: Paginated,
        which: Which,
        reference: impl Into<SbomPackageReference<'_>> + Debug,
        relationship: Option<Relationship>,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackageRelation>, Error> {
        let connection = self.db.connection(&tx);

        // which way

        log::info!("Which: {which:?}");

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
            // join the other side
            .join(JoinType::Join, join.def())
            .join(JoinType::Join, sbom_node::Relation::Package.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
            .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def());

        // collect PURLs and CPEs

        let query = join_purls_and_cpes(query);

        // filter for reference

        let query = match reference.into() {
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

        // FIXME: disabled due to https://github.com/trustification/trustify/issues/291
        // let mut query = query.filtering(search)?;

        // add relationship type filter

        let mut query = query;
        if let Some(relationship) = relationship {
            query = query.filter(package_relates_to_package::Column::Relationship.eq(relationship));
        }

        // limit and execute

        let limiter =
            limit_selector::<'_, _, _, _, Row>(&self.db, query, paginated.offset, paginated.limit);

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
                     purls,
                     cpes,
                 }| SbomPackageRelation {
                    package: package_from_row(id, name, purls, cpes),
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
fn package_from_row(id: String, name: String, purls: Vec<Value>, cpes: Vec<Value>) -> SbomPackage {
    SbomPackage {
        id,
        name,
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
    use trustify_common::db::test::TrustifyContext;
    use trustify_module_ingestor::graph::Graph;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test(tokio::test)]
    async fn all_sboms(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let system = Graph::new(db.clone());

        let sbom_v1 = system
            .ingest_sbom(
                "http://redhat.com/test.json",
                "8",
                "a",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v1_again = system
            .ingest_sbom(
                "http://redhat.com/test.json",
                "8",
                "a",
                (),
                Transactional::None,
            )
            .await?;
        let sbom_v2 = system
            .ingest_sbom(
                "http://myspace.com/test.json",
                "9",
                "b",
                (),
                Transactional::None,
            )
            .await?;

        let _other_sbom = system
            .ingest_sbom(
                "http://geocities.com/other.json",
                "10",
                "c",
                (),
                Transactional::None,
            )
            .await?;

        assert_eq!(sbom_v1.sbom.sbom_id, sbom_v1_again.sbom.sbom_id);
        assert_ne!(sbom_v1.sbom.sbom_id, sbom_v2.sbom.sbom_id);

        let fetch = FetchService::new(db);

        let fetched = fetch
            .fetch_sboms(
                SearchOptions {
                    q: "MySpAcE".to_string(),
                    ..Default::default()
                },
                Paginated::default(),
                (),
            )
            .await?;

        assert_eq!(1, fetched.total);

        Ok(())
    }
}
