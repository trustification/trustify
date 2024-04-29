use super::FetchService;
use crate::model::sbom::SbomPackage;
use crate::{
    error::Error,
    model::{
        advisory::{AdvisorySummary, AdvisoryVulnerabilitySummary},
        sbom::SbomSummary,
    },
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, RelationTrait};
use sea_query::JoinType;
use trustify_common::{
    db::limiter::LimiterTrait,
    db::Transactional,
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{package, package_version, qualified_package, sbom, sbom_describes_package};
use trustify_module_search::{model::SearchOptions, query::Query};

impl FetchService {
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
                identifier: sbom.id,
                sha256: sbom.sha256,
                document_id: sbom.document_id,

                title: sbom.title,
                published: sbom.published,
            })
        }

        Ok(PaginatedResults { total, items })
    }

    pub async fn fetch_sbom_packages<TX: AsRef<Transactional>>(
        &self,
        sbom_id: i32,
        search: SearchOptions,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<SbomPackage>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = qualified_package::Entity::find()
            .join(
                JoinType::Join,
                qualified_package::Relation::PackageVersion.def(),
            )
            .join(JoinType::Join, package_version::Relation::Package.def())
            .join_rev(
                JoinType::Join,
                sbom_describes_package::Relation::Package.def(),
            )
            .filter(sbom_describes_package::Column::SbomId.eq(sbom_id))
            .filtering(search)?
            .limiting(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let sboms = limiter.fetch().await?;

        let mut items = Vec::new();
        for sbom in sboms {
            items.push(SbomPackage {
                purl: "foo".to_string(),
            })
        }

        Ok(PaginatedResults { total, items })
    }
}
