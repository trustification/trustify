use crate::{
    license::model::{
        LicenseDetailsPurlSummary, LicenseSummary, SpdxLicenseDetails, SpdxLicenseSummary,
    },
    purl::model::VersionedPurlHead,
    sbom::model::SbomHead,
    Error,
};
use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, FromQueryResult, ModelTrait, PaginatorTrait, QueryFilter,
    QueryResult, QuerySelect, RelationTrait, Select, TransactionTrait,
};
use sea_query::JoinType;
use trustify_common::{
    db::{
        limiter::{LimiterAsModelTrait, LimiterTrait},
        multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        query::{Filtering, Query},
        Database,
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{base_purl, license, purl_license_assertion, sbom, versioned_purl};
use uuid::Uuid;

pub struct LicenseService {
    db: Database,
}

impl LicenseService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list_licenses(
        &self,
        search: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<LicenseSummary>, Error> {
        let tx = self.db.begin().await?;

        let limiter = license::Entity::find().filtering(search)?.limiting(
            &self.db,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            items: LicenseSummary::from_entities(&limiter.fetch().await?, &tx).await?,
            total,
        })
    }

    pub async fn get_license(&self, id: Uuid) -> Result<Option<LicenseSummary>, Error> {
        let tx = self.db.begin().await?;

        if let Some(license) = license::Entity::find_by_id(id).one(&tx).await? {
            let purls = license
                .find_related(purl_license_assertion::Entity)
                .count(&tx)
                .await?;
            return Ok(Some(LicenseSummary::from_entity(&license, purls).await?));
        }

        Ok(None)
    }

    pub async fn get_license_purls(
        &self,
        id: Uuid,
        query: Query,
        pagination: Paginated,
    ) -> Result<PaginatedResults<LicenseDetailsPurlSummary>, Error> {
        #[derive(Debug)]
        struct PurlLicenseCatcher {
            base_purl: base_purl::Model,
            versioned_purl: versioned_purl::Model,
            sbom: sbom::Model,
        }

        impl FromQueryResult for PurlLicenseCatcher {
            fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
                Ok(Self {
                    base_purl: Self::from_query_result_multi_model(res, "", base_purl::Entity)?,
                    versioned_purl: Self::from_query_result_multi_model(
                        res,
                        "",
                        versioned_purl::Entity,
                    )?,
                    sbom: Self::from_query_result_multi_model(res, "", sbom::Entity)?,
                })
            }
        }

        impl FromQueryResultMultiModel for PurlLicenseCatcher {
            fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
                select
                    .try_model_columns(base_purl::Entity)?
                    .try_model_columns(versioned_purl::Entity)?
                    .try_model_columns(sbom::Entity)
            }
        }

        let tx = self.db.begin().await?;

        let licensed_purls = versioned_purl::Entity::find()
            .join(JoinType::Join, versioned_purl::Relation::BasePurl.def())
            .join(
                JoinType::Join,
                versioned_purl::Relation::LicenseAssertions.def(),
            )
            .join(
                JoinType::Join,
                purl_license_assertion::Relation::License.def(),
            )
            .join(JoinType::Join, purl_license_assertion::Relation::Sbom.def())
            .filter(license::Column::Id.eq(id))
            .filtering(query)?
            .try_limiting_as_multi_model::<PurlLicenseCatcher>(
                &tx,
                pagination.offset,
                pagination.limit,
            )?;

        let total = licensed_purls.total().await?;

        let mut items = Vec::new();

        for row in licensed_purls.fetch().await? {
            items.push(LicenseDetailsPurlSummary {
                purl: VersionedPurlHead::from_entity(&row.base_purl, &row.versioned_purl, &tx)
                    .await?,
                sbom: SbomHead::from_entity(&row.sbom, None, &tx).await?,
            })
        }

        Ok(PaginatedResults { items, total })
    }

    pub async fn list_spdx_licenses(
        &self,
        search: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<SpdxLicenseSummary>, Error> {
        let all_matching = spdx::identifiers::LICENSES
            .iter()
            .filter(|(identifier, name, _)| {
                search.q.is_empty()
                    || identifier.to_lowercase().contains(&search.q.to_lowercase())
                    || name.to_lowercase().contains(&search.q.to_lowercase())
            })
            .collect::<Vec<_>>();

        if all_matching.len() < paginated.offset as usize {
            return Ok(PaginatedResults {
                items: vec![],
                total: all_matching.len() as u64,
            });
        }

        let matching = &all_matching[paginated.offset as usize..];

        if paginated.limit > 0 && matching.len() > paginated.limit as usize {
            Ok(PaginatedResults {
                items: SpdxLicenseSummary::from_details(&matching[..paginated.limit as usize]),
                total: all_matching.len() as u64,
            })
        } else {
            Ok(PaginatedResults {
                items: SpdxLicenseSummary::from_details(matching),
                total: all_matching.len() as u64,
            })
        }
    }

    pub async fn get_spdx_license(&self, id: &str) -> Result<Option<SpdxLicenseDetails>, Error> {
        if let Some((spdx_identifier, spdx_name, _)) = spdx::identifiers::LICENSES
            .iter()
            .find(|(identifier, _name, _flags)| identifier.eq_ignore_ascii_case(id))
        {
            if let Some(text) = spdx::text::LICENSE_TEXTS
                .iter()
                .find_map(|(identifier, text)| {
                    if identifier.eq_ignore_ascii_case(spdx_identifier) {
                        Some(text.to_string())
                    } else {
                        None
                    }
                })
            {
                return Ok(Some(SpdxLicenseDetails {
                    summary: SpdxLicenseSummary {
                        id: spdx_identifier.to_string(),
                        name: spdx_name.to_string(),
                    },
                    text,
                }));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test;
