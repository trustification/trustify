use crate::{
    Error,
    license::model::{
        SpdxLicenseDetails, SpdxLicenseSummary,
        sbom_license::{
            ExtractedLicensingInfos, Purl, SbomNameGroupVersion, SbomPackageLicense,
            SbomPackageLicenseBase,
        },
    },
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, RelationTrait};
use sea_query::{Condition, JoinType};
use trustify_common::{
    db::{
        Database,
        // limiter::{LimiterAsModelTrait, LimiterTrait},
        // multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        query::Query,
    },
    id::{Id, TrySelectForId},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::sbom_package_license::LicenseCategory;
use trustify_entity::{
    license, licensing_infos, package_relates_to_package, qualified_purl, sbom, sbom_node,
    sbom_package, sbom_package_cpe_ref, sbom_package_license, sbom_package_purl_ref,
};

pub mod license_export;

pub struct LicenseService {
    // db: Database,
}

impl LicenseService {
    pub fn new(_db: Database) -> Self {
        Self {}
    }

    pub async fn license_export<C: ConnectionTrait>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<
        (
            Vec<SbomPackageLicense>,
            Vec<ExtractedLicensingInfos>,
            Option<SbomNameGroupVersion>,
        ),
        Error,
    > {
        let name_version_group: Option<SbomNameGroupVersion> = sbom::Entity::find()
            .try_filter(id.clone())?
            .join(JoinType::Join, sbom::Relation::SbomNode.def())
            .join(JoinType::Join, sbom_node::Relation::DescribesSbom.def())
            .join(
                JoinType::Join,
                package_relates_to_package::Relation::RightPackage.def(),
            )
            .select_only()
            .column_as(sbom_node::Column::Name, "sbom_name")
            .column_as(sbom_package::Column::Group, "sbom_group")
            .column_as(sbom_package::Column::Version, "sbom_version")
            .into_model::<SbomNameGroupVersion>()
            .one(connection)
            .await?;

        let package_license: Vec<SbomPackageLicenseBase> = sbom::Entity::find()
            .try_filter(id.clone())?
            .join(JoinType::LeftJoin, sbom::Relation::Packages.def())
            .join(JoinType::InnerJoin, sbom_package::Relation::Node.def())
            .join(
                JoinType::LeftJoin,
                sbom_package::Relation::PackageLicense.def(),
            )
            .join(
                JoinType::InnerJoin,
                sbom_package_license::Relation::License.def(),
            )
            .filter(
                Condition::all()
                    .add(sbom_package_license::Column::LicenseType.eq(LicenseCategory::Declared)),
            )
            .select_only()
            .column_as(sbom::Column::SbomId, "sbom_id")
            .column_as(sbom::Column::DocumentId, "sbom_namespace")
            .column_as(sbom_package::Column::NodeId, "node_id")
            .column_as(sbom_node::Column::Name, "package_name")
            .column_as(license::Column::Text, "license_text")
            .into_model::<SbomPackageLicenseBase>()
            .all(connection)
            .await?;

        let mut sbom_package_list = Vec::new();
        for spl in package_license {
            let result_purl: Vec<Purl> = sbom_package_purl_ref::Entity::find()
                .join(JoinType::Join, sbom_package_purl_ref::Relation::Purl.def())
                .filter(
                    Condition::all()
                        .add(sbom_package_purl_ref::Column::NodeId.eq(spl.node_id.clone()))
                        .add(sbom_package_purl_ref::Column::SbomId.eq(spl.sbom_id)),
                )
                .select_only()
                .column_as(qualified_purl::Column::Purl, "purl")
                .into_model::<Purl>()
                .all(connection)
                .await?;
            let result_cpe: Vec<trustify_entity::cpe::Model> = sbom_package_cpe_ref::Entity::find()
                .join(JoinType::Join, sbom_package_cpe_ref::Relation::Cpe.def())
                .filter(
                    Condition::all()
                        .add(sbom_package_cpe_ref::Column::NodeId.eq(spl.node_id.clone()))
                        .add(sbom_package_cpe_ref::Column::SbomId.eq(spl.sbom_id)),
                )
                .select_only()
                .column_as(trustify_entity::cpe::Column::Id, "id")
                .column_as(trustify_entity::cpe::Column::Part, "cpe")
                .column_as(trustify_entity::cpe::Column::Vendor, "vendor")
                .column_as(trustify_entity::cpe::Column::Product, "product")
                .column_as(trustify_entity::cpe::Column::Version, "version")
                .column_as(trustify_entity::cpe::Column::Update, "update")
                .column_as(trustify_entity::cpe::Column::Edition, "edition")
                .column_as(trustify_entity::cpe::Column::Language, "language")
                .into_model::<trustify_entity::cpe::Model>()
                .all(connection)
                .await?;

            sbom_package_list.push(SbomPackageLicense {
                sbom_namespace: spl.sbom_namespace,
                name: spl.package_name,
                purl: result_purl,
                other_reference: result_cpe,
                license_text: spl.license_text,
            });
        }
        let license_info_list: Vec<ExtractedLicensingInfos> = licensing_infos::Entity::find()
            .filter(
                Condition::all()
                    .add(licensing_infos::Column::SbomId.eq(id.try_as_uid().unwrap_or_default())),
            )
            .select_only()
            .column_as(licensing_infos::Column::LicenseId, "license_id")
            .column_as(licensing_infos::Column::Name, "name")
            .column_as(licensing_infos::Column::ExtractedText, "extracted_text")
            .column_as(licensing_infos::Column::Comment, "comment")
            .into_model::<ExtractedLicensingInfos>()
            .all(connection)
            .await?;
        Ok((sbom_package_list, license_info_list, name_version_group))
    }

    // pub async fn list_licenses(
    //     &self,
    //     search: Query,
    //     paginated: Paginated,
    // ) -> Result<PaginatedResults<LicenseSummary>, Error> {
    //     let tx = self.db.begin().await?;
    //
    //     let limiter = license::Entity::find().filtering(search)?.limiting(
    //         &self.db,
    //         paginated.offset,
    //         paginated.limit,
    //     );
    //
    //     let total = limiter.total().await?;
    //
    //     Ok(PaginatedResults {
    //         items: LicenseSummary::from_entities(&limiter.fetch().await?, &tx).await?,
    //         total,
    //     })
    // }

    // pub async fn get_license(&self, id: Uuid) -> Result<Option<LicenseSummary>, Error> {
    //     let tx = self.db.begin().await?;
    //
    //     if let Some(license) = license::Entity::find_by_id(id).one(&tx).await? {
    //         let purls = license
    //             .find_related(purl_license_assertion::Entity)
    //             .count(&tx)
    //             .await?;
    //         return Ok(Some(LicenseSummary::from_entity(&license, purls).await?));
    //     }
    //
    //     Ok(None)
    // }

    // pub async fn get_license_purls(
    //     &self,
    //     id: Uuid,
    //     query: Query,
    //     pagination: Paginated,
    // ) -> Result<PaginatedResults<LicenseDetailsPurlSummary>, Error> {
    //     #[derive(Debug)]
    //     struct PurlLicenseCatcher {
    //         base_purl: base_purl::Model,
    //         versioned_purl: versioned_purl::Model,
    //         sbom: sbom::Model,
    //     }
    //
    //     impl FromQueryResult for PurlLicenseCatcher {
    //         fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
    //             Ok(Self {
    //                 base_purl: Self::from_query_result_multi_model(res, "", base_purl::Entity)?,
    //                 versioned_purl: Self::from_query_result_multi_model(
    //                     res,
    //                     "",
    //                     versioned_purl::Entity,
    //                 )?,
    //                 sbom: Self::from_query_result_multi_model(res, "", sbom::Entity)?,
    //             })
    //         }
    //     }
    //
    //     impl FromQueryResultMultiModel for PurlLicenseCatcher {
    //         fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
    //             select
    //                 .try_model_columns(base_purl::Entity)?
    //                 .try_model_columns(versioned_purl::Entity)?
    //                 .try_model_columns(sbom::Entity)
    //         }
    //     }
    //
    //     let tx = self.db.begin().await?;
    //
    //     // let licensed_purls = versioned_purl::Entity::find()
    //     //     .join(JoinType::Join, versioned_purl::Relation::BasePurl.def())
    //     //     .join(
    //     //         JoinType::Join,
    //     //         versioned_purl::Relation::LicenseAssertions.def(),
    //     //     )
    //     //     .join(
    //     //         JoinType::Join,
    //     //         purl_license_assertion::Relation::License.def(),
    //     //     )
    //     //     .join(JoinType::Join, purl_license_assertion::Relation::Sbom.def())
    //     //     .filter(license::Column::Id.eq(id))
    //     //     .filtering(query)?
    //     //     .try_limiting_as_multi_model::<PurlLicenseCatcher>(
    //     //         &tx,
    //     //         pagination.offset,
    //     //         pagination.limit,
    //     //     )?;
    //
    //     let total = licensed_purls.total().await?;
    //
    //     let mut items = Vec::new();
    //
    //     for row in licensed_purls.fetch().await? {
    //         items.push(LicenseDetailsPurlSummary {
    //             purl: VersionedPurlHead::from_entity(&row.base_purl, &row.versioned_purl, &tx)
    //                 .await?,
    //             sbom: SbomHead::from_entity(&row.sbom, None, &tx).await?,
    //         })
    //     }
    //
    //     Ok(PaginatedResults { items, total })
    // }

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
