use super::FetchService;
use crate::query::{Query, SearchOptions};
use crate::{
    error::Error,
    model::{
        advisory::{AdvisorySummary, AdvisoryVulnerabilitySummary},
        sbom::{SbomPackage, SbomPackageRelation, SbomSummary},
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, LoaderTrait, QueryFilter, QueryOrder, QuerySelect,
    RelationTrait, Select, SelectorTrait,
};
use sea_query::{Alias, Expr, IntoColumnRef, IntoTableRef, JoinType};
use std::iter::{repeat, Flatten, Zip};
use std::vec::IntoIter;
use trustify_common::{
    db::{
        limiter::{Limiter, LimiterTrait},
        Transactional,
    },
    model::{Paginated, PaginatedResults},
    purl::Purl,
};
use trustify_entity::{
    package, package_relates_to_package, package_version, qualified_package,
    relationship::Relationship, sbom, sbom_package,
};

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

        let limiter = sbom::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;
        let sboms = limiter.fetch().await?;

        let mut items = Vec::new();
        for sbom in sboms {
            items.push(SbomSummary {
                id: sbom.id,
                sha256: sbom.sha256,
                document_id: sbom.document_id,

                title: sbom.title,
                published: sbom.published,
                authors: sbom.authors,
            })
        }

        Ok(PaginatedResults { total, items })
    }

    /// fetch all packages from an SBOM
    pub async fn fetch_sbom_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: i32,
        search: SearchOptions,
        paginated: Paginated,
        root: bool,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackage>, Error> {
        let connection = self.db.connection(&tx);

        // TODO: select all sbom_packages, maybe then load purls and cpes
        let mut query = qualified_package::Entity::find()
            .join(JoinType::Join, sbom_package::Relation::Package.def().rev())
            .join(
                JoinType::Join,
                qualified_package::Relation::PackageVersion.def(),
            )
            .join(JoinType::Join, package_version::Relation::Package.def())
            .filter(sbom_package::Column::SbomId.eq(sbom_id))
            .filtering(search)?;

        // TODO: we might reconsider this, root level stuff can be found using document id ref
        if root {
            // limit to root level packages
            query = query
                .join_rev(
                    JoinType::LeftJoin,
                    package_relates_to_package::Relation::Left.def(),
                )
                // limit no-relationship
                .filter(package_relates_to_package::Column::LeftPackageId.is_null());
        }

        let query = default_sort(query);

        let limiter = query.limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let qualified = limiter.fetch().await?;

        let items = purl_result(
            &connection,
            qualified,
            |i| i.zip(repeat(())),
            |package, version, qualified, _| {
                let purl = into_purl(package, version, qualified).to_string();
                SbomPackage { purl }
            },
        )
        .await?;

        Ok(PaginatedResults { items, total })
    }

    /// fetch all packages from an SBOM
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch_related_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: i32,
        search: SearchOptions,
        paginated: Paginated,
        which: Which,
        reference: Purl,
        relationship: Option<Relationship>,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackageRelation>, Error> {
        let connection = self.db.connection(&tx);

        // which way

        log::info!("Which: {which:?}");

        // select all qualified packages for which we have relationships

        let (filter, join) = match which {
            Which::Left => (
                package_relates_to_package::Column::LeftPackageId,
                package_relates_to_package::Relation::Right,
            ),
            Which::Right => (
                package_relates_to_package::Column::RightPackageId,
                package_relates_to_package::Relation::Left,
            ),
        };

        let mut query = qualified_package::Entity::find()
            .join_rev(JoinType::Join, join.def())
            .join(
                JoinType::Join,
                qualified_package::Relation::PackageVersion.def(),
            )
            .join(JoinType::Join, package_version::Relation::Package.def())
            // limit by sbom
            .filter(package_relates_to_package::Column::SbomId.eq(sbom_id))
            // limit by "which" side package
            .filter(filter.eq(reference.qualifier_uuid()))
            .filtering(search)?;

        if let Some(relationship) = relationship {
            query = query.filter(package_relates_to_package::Column::Relationship.eq(relationship));
        }

        let query = default_sort(query);
        let query = query.select_also(package_relates_to_package::Entity);

        let limiter = query.limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let (qualified, rel): (Vec<_>, Vec<_>) = limiter.fetch().await?.into_iter().unzip();

        let items = purl_result(
            &connection,
            qualified,
            move |i| i.zip(rel.into_iter().flatten()),
            |package, version, qualified, rel| {
                let purl = into_purl(package, version, qualified).to_string();
                SbomPackageRelation {
                    package: purl.to_string(),
                    relationship: rel.relationship,
                }
            },
        )
        .await?;

        Ok(PaginatedResults { items, total })
    }
}

/// apply default sort order, by purl
fn default_sort(query: Select<qualified_package::Entity>) -> Select<qualified_package::Entity> {
    query
        .order_by_asc(package::Column::Type)
        .order_by_asc(package::Column::Name)
        .order_by_asc(package_version::Column::Version)
        .order_by_asc(qualified_package::Column::Id)
}

fn into_purl(
    package: package::Model,
    version: package_version::Model,
    qualified: qualified_package::Model,
) -> Purl {
    Purl {
        ty: package.r#type,
        namespace: package.namespace,
        name: package.name,
        version: if version.version.is_empty() {
            None
        } else {
            Some(version.version)
        },
        qualifiers: qualified.qualifiers.0,
    }
}

async fn purl_result<'db, T, C, I, Out, F, X>(
    connection: &C,
    qualified: Vec<qualified_package::Model>,
    i: I,
    f: F,
) -> Result<Vec<T>, Error>
where
    C: ConnectionTrait,
    I: FnOnce(
        Zip<
            Zip<IntoIter<qualified_package::Model>, IntoIter<package_version::Model>>,
            Flatten<IntoIter<Option<package::Model>>>,
        >,
    ) -> Out,
    Out: Iterator<
        Item = (
            (
                (qualified_package::Model, package_version::Model),
                package::Model,
            ),
            X,
        ),
    >,
    F: Fn(package::Model, package_version::Model, qualified_package::Model, X) -> T,
{
    let package_version = qualified
        .load_one(package_version::Entity, connection)
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let package = package_version
        .load_one(package::Entity, connection)
        .await?
        .into_iter()
        .flatten();

    let mut items = Vec::new();
    for (((qualified, version), package), x) in i(qualified
        .into_iter()
        .zip(package_version.into_iter())
        .zip(package))
    {
        items.push(f(package, version, qualified, x))
    }

    Ok(items)
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

        assert_eq!(sbom_v1.sbom.id, sbom_v1_again.sbom.id);
        assert_ne!(sbom_v1.sbom.id, sbom_v2.sbom.id);

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
