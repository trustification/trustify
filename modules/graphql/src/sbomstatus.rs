use async_graphql::{Context, FieldResult, Object};
use std::{ops::Deref, sync::Arc};
use trustify_common::{
    db::{self, Transactional},
    id::Id,
};
use trustify_module_fundamental::sbom::{
    model::details::{SbomDetails, SbomStatus},
    service::SbomService,
};
use uuid::Uuid;

#[derive(Default)]
pub struct SbomStatusQuery;

#[Object]
impl SbomStatusQuery {
    async fn cves_by_sbom<'a>(&self, ctx: &Context<'a>, id: Uuid) -> FieldResult<Vec<SbomStatus>> {
        let db = ctx.data::<Arc<db::Database>>()?;
        let sbom_service = SbomService::new(db.deref().clone());

        let sbom_details: Option<SbomDetails> = sbom_service
            .fetch_sbom_details(Id::Uuid(id), Transactional::None)
            .await
            .unwrap_or_default();

        Ok(sbom_details
            .and_then(|mut sbom| sbom.advisories.pop().map(|advisory| advisory.status))
            .unwrap_or_default())
    }
}
