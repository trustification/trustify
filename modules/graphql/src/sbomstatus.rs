use async_graphql::{Context, FieldResult, Object, SimpleObject};
use std::{ops::Deref, sync::Arc};
use trustify_common::{
    db::{self, Transactional},
    id::Id,
};
use trustify_module_fundamental::{
    purl::model::details::purl::StatusContext,
    sbom::{
        model::{
            details::{SbomDetails, SbomStatus},
            SbomPackage,
        },
        service::SbomService,
    },
};
use uuid::Uuid;

#[derive(Default)]
pub struct SbomStatusQuery;

#[Object]
impl SbomStatusQuery {
    async fn cves_by_sbom<'a>(
        &self,
        ctx: &Context<'a>,
        id: Uuid,
    ) -> FieldResult<Vec<GraphQLSbomStatus>> {
        let db = ctx.data::<Arc<db::Database>>()?;
        let sbom_service = SbomService::new(db.deref().clone());

        let sbom_details: Option<SbomDetails> = sbom_service
            .fetch_sbom_details(Id::Uuid(id), Transactional::None)
            .await
            .unwrap_or_default();

        Ok(sbom_details
            .and_then(|mut sbom| {
                sbom.advisories.pop().map(|advisory| {
                    advisory
                        .status
                        .into_iter()
                        .map(GraphQLSbomStatus::from)
                        .collect()
                })
            })
            .unwrap_or_default())
    }
}

#[derive(Clone, Debug, SimpleObject)]
#[graphql(concrete(name = "SbomStatus", params()))]
pub struct GraphQLSbomStatus {
    pub vulnerability_id: String,
    pub status: String,
    #[graphql(skip)]
    pub context: Option<StatusContext>,
    pub packages: Vec<SbomPackage>,
}

impl GraphQLSbomStatus {}

impl From<SbomStatus> for GraphQLSbomStatus {
    fn from(sbom_status: SbomStatus) -> Self {
        GraphQLSbomStatus {
            vulnerability_id: sbom_status.vulnerability.identifier.clone(),
            status: sbom_status.status,
            context: sbom_status.context,
            packages: sbom_status.packages,
        }
    }
}
